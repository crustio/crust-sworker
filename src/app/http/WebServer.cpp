#include "WebServer.h"

#include <stdio.h>
#include <iostream>
#include <algorithm>
#include <mutex>
#include <exception>
#include <sgx_report.h>
#include <sgx_key_exchange.h>
#include <sgx_error.h>
#include "ECalls.h"
#include "sgx_eid.h"
#include "Common.h"
#include "Config.h"
#include "FormatUtils.h"
#include "SgxSupport.h"
#include "Resource.h"
#include "FileUtils.h"
#include "Log.h"
#include "Json.hpp"
#include "sgx_tseal.h"
#include "Json.hpp"


namespace beast = boost::beast;                 // from <boost/beast.hpp>
namespace http = beast::http;                   // from <boost/beast/http.hpp>
namespace websocket = beast::websocket;         // from <boost/beast/websocket.hpp>
namespace net = boost::asio;                    // from <boost/asio.hpp>
namespace ssl = boost::asio::ssl;               // from <boost/asio/ssl.hpp>
using tcp = boost::asio::ip::tcp;               // from <boost/asio/ip/tcp.hpp>

crust::Log *p_log = crust::Log::get_instance();

std::shared_ptr<net::io_context> p_ioc = NULL;
pid_t g_webservice_pid;

int g_start_server_success = -1;

// Return a reasonable mime type based on the extension of a file.
beast::string_view mime_type(beast::string_view path)
{
    using beast::iequals;
    auto const ext = [&path]
    {
        auto const pos = path.rfind(".");
        if(pos == beast::string_view::npos)
            return beast::string_view{};
        return path.substr(pos);
    }();
    if(iequals(ext, ".htm"))  return "text/html";
    if(iequals(ext, ".html")) return "text/html";
    if(iequals(ext, ".php"))  return "text/html";
    if(iequals(ext, ".css"))  return "text/css";
    if(iequals(ext, ".txt"))  return "text/plain";
    if(iequals(ext, ".js"))   return "application/javascript";
    if(iequals(ext, ".json")) return "application/json";
    if(iequals(ext, ".xml"))  return "application/xml";
    if(iequals(ext, ".swf"))  return "application/x-shockwave-flash";
    if(iequals(ext, ".flv"))  return "video/x-flv";
    if(iequals(ext, ".png"))  return "image/png";
    if(iequals(ext, ".jpe"))  return "image/jpeg";
    if(iequals(ext, ".jpeg")) return "image/jpeg";
    if(iequals(ext, ".jpg"))  return "image/jpeg";
    if(iequals(ext, ".gif"))  return "image/gif";
    if(iequals(ext, ".bmp"))  return "image/bmp";
    if(iequals(ext, ".ico"))  return "image/vnd.microsoft.icon";
    if(iequals(ext, ".tiff")) return "image/tiff";
    if(iequals(ext, ".tif"))  return "image/tiff";
    if(iequals(ext, ".svg"))  return "image/svg+xml";
    if(iequals(ext, ".svgz")) return "image/svg+xml";
    return "application/text";
}

//------------------------------------------------------------------------------

// Report a failure
void fail(beast::error_code ec, char const* what)
{
    // ssl::error::stream_truncated, also known as an SSL "short read",
    // indicates the peer closed the connection without performing the
    // required closing handshake (for example, Google does this to
    // improve performance). Generally this can be a security issue,
    // but if your communication protocol is self-terminated (as
    // it is with both HTTP and WebSocket) then you may simply
    // ignore the lack of close_notify.
    //
    // https://github.com/boostorg/beast/issues/38
    //
    // https://security.stackexchange.com/questions/91435/how-to-handle-a-malicious-ssl-tls-shutdown
    //
    // When a short read would cut off the end of an HTTP message,
    // Beast returns the error beast::http::error::partial_message.
    // Therefore, if we see a short read here, it has occurred
    // after the message has been completed, so it is safe to ignore it.

    if(ec == net::ssl::error::stream_truncated)
        return;

    p_log->err("Webserver error: %s : %s\n", what, ec.message().c_str());
    //std::cerr << what << ": " << ec.message() << "\n";
}

//------------------------------------------------------------------------------

// Echoes back all received WebSocket messages.
// This uses the Curiously Recurring Template Pattern so that
// the same code works with both SSL streams and regular sockets.
template<class Derived>
class websocket_session
{
    // Access the derived class, this is part of
    // the Curiously Recurring Template Pattern idiom.
    Derived& derived()
    {
        return static_cast<Derived&>(*this);
    }

    beast::flat_buffer buffer_;
    ApiHandler *api_handler_;
    std::string path_;
    bool close_connection_;

    // Start the asynchronous operation
    template<class Body, class Allocator>
    void do_accept(http::request<Body, http::basic_fields<Allocator>> req)
    {
        // Get base path
        path_ = req.target().data();

        // Set suggested timeout settings for the websocket
        derived().ws().set_option(
            websocket::stream_base::timeout::suggested(
                beast::role_type::server));

        // Set a decorator to change the Server of the handshake
        derived().ws().set_option(
            websocket::stream_base::decorator(
            [](websocket::response_type& res)
            {
                res.set(http::field::server,
                    std::string(BOOST_BEAST_VERSION_STRING) +
                        " advanced-server-flex");
            }));

        // Accept the websocket handshake
        derived().ws().async_accept(
            req,
            beast::bind_front_handler(
                &websocket_session::on_accept,
                derived().shared_from_this()));
    }

    void on_accept(beast::error_code ec)
    {
        if(ec)
            return fail(ec, "accept");

        // Read a message
        do_read();
    }

    void do_read()
    {
        // Read a message into our buffer
        derived().ws().async_read(
            buffer_,
            beast::bind_front_handler(
                &websocket_session::on_read,
                derived().shared_from_this()));
    }

    void on_read(beast::error_code ec, std::size_t bytes_transferred)
    {
        boost::ignore_unused(bytes_transferred);

        // This indicates that the websocket_session was closed
        if(ec == websocket::error::closed)
            return;

        if(ec)
        {
            fail(ec, "read");
            return;
        }

        // Deal the message
        std::string buf = beast::buffers_to_string(buffer_.data());
        close_connection_ = false;
        std::string res = api_handler_->websocket_handler(path_, buf, close_connection_);

        // ----- Async write data ----- //
        derived().ws().async_write(
            boost::asio::buffer(res.c_str(), res.size()),
            beast::bind_front_handler(
                &websocket_session::on_write,
                derived().shared_from_this()));
    }

    void on_write(beast::error_code ec, std::size_t bytes_transferred)
    {
        boost::ignore_unused(bytes_transferred);

        if(ec)
        {
            return fail(ec, "write");
        }

        // Clear the buffer
        buffer_.consume(buffer_.size());

        if (close_connection_)
            return;

        // Do another read
        do_read();
    }

public:

    websocket_session(ApiHandler *api_handler): api_handler_(api_handler) {}

    // Start the asynchronous operation
    template<class Body, class Allocator>
    void run(http::request<Body, http::basic_fields<Allocator>> req)
    {
        // Accept the WebSocket upgrade request
        do_accept(std::move(req));
    }
};

//------------------------------------------------------------------------------

// Handles a plain WebSocket connection
class plain_websocket_session
    : public websocket_session<plain_websocket_session>
    , public std::enable_shared_from_this<plain_websocket_session>
{
    websocket::stream<beast::tcp_stream> ws_;

public:
    // Create the session
    explicit
    plain_websocket_session(
        beast::tcp_stream&& stream,
        ApiHandler *api_handler)
        : websocket_session<plain_websocket_session>(api_handler)
        , ws_(std::move(stream))
    {
    }

    // Called by the base class
    websocket::stream<beast::tcp_stream>& ws()
    {
        return ws_;
    }
};

//------------------------------------------------------------------------------

// Handles an SSL WebSocket connection
class ssl_websocket_session
    : public websocket_session<ssl_websocket_session>
    , public std::enable_shared_from_this<ssl_websocket_session>
{
    websocket::stream<
        beast::ssl_stream<beast::tcp_stream>> ws_;

public:
    // Create the ssl_websocket_session
    explicit
    ssl_websocket_session(
        beast::ssl_stream<beast::tcp_stream>&& stream,
        ApiHandler *api_handler)
        : websocket_session<ssl_websocket_session>(api_handler)
        , ws_(std::move(stream))
    {
    }

    // Called by the base class
    websocket::stream<beast::ssl_stream<beast::tcp_stream>>& ws()
    {
        return ws_;
    }
};

//------------------------------------------------------------------------------

template<class Body, class Allocator>
void
make_websocket_session(
    beast::tcp_stream stream,
    http::request<Body, http::basic_fields<Allocator>> req,
    ApiHandler *api_handler)
{
    std::make_shared<plain_websocket_session>(
        std::move(stream), api_handler)->run(std::move(req));
}

template<class Body, class Allocator>
void
make_websocket_session(
    beast::ssl_stream<beast::tcp_stream> stream,
    http::request<Body, http::basic_fields<Allocator>> req,
    ApiHandler *api_handler)
{
    std::make_shared<ssl_websocket_session>(
        std::move(stream), api_handler)->run(std::move(req));
}

//------------------------------------------------------------------------------

// Handles an HTTP server connection.
// This uses the Curiously Recurring Template Pattern so that
// the same code works with both SSL streams and regular sockets.
template<class Derived>
class http_session
{
    // Access the derived class, this is part of
    // the Curiously Recurring Template Pattern idiom.
    Derived& derived()
    {
        return static_cast<Derived&>(*this);
    }

    // This Queue is used for HTTP pipelining.
    class Queue
    {
        enum
        {
            // Maximum number of responses we will Queue
            //limit = 8
            limit = 64
        };

        // The type-erased, saved work item
        struct work
        {
            virtual ~work() = default;
            virtual void operator()() = 0;
        };

        http_session& self_;
        std::vector<std::unique_ptr<work>> items_;

    public:
        explicit Queue(http_session& self)
            : self_(self)
        {
            static_assert(limit > 0, "Queue limit must be positive");
            items_.reserve(limit);
        }

        // Returns `true` if we have reached the Queue limit
        bool is_full() const
        {
            return items_.size() >= limit;
        }

        // Called when a message finishes sending
        // Returns `true` if the caller should initiate a read
        bool on_write()
        {
            BOOST_ASSERT(! items_.empty());
            auto const was_full = is_full();
            items_.erase(items_.begin());
            if(! items_.empty())
                (*items_.front())();
            return was_full;
        }

        // Called by the HTTP handler to send a response.
        template<bool isRequest, class Body, class Fields>
        void operator()(http::message<isRequest, Body, Fields>&& msg)
        {
            // This holds a work item
            struct work_impl : work
            {
                http_session& self_;
                http::message<isRequest, Body, Fields> msg_;

                work_impl(
                    http_session& self,
                    http::message<isRequest, Body, Fields>&& msg)
                    : self_(self)
                    , msg_(std::move(msg))
                {
                }

                void
                operator()()
                {
                    http::async_write(
                        self_.derived().stream(),
                        msg_,
                        beast::bind_front_handler(
                            &http_session::on_write,
                            self_.derived().shared_from_this(),
                            msg_.need_eof()));
                }
            };

            // Allocate and store the work
            items_.push_back(
                boost::make_unique<work_impl>(self_, std::move(msg)));

            // If there was no previous work, start this one
            if(items_.size() == 1)
                (*items_.front())();
        }
    };

    std::shared_ptr<std::string const> doc_root_;
    Queue queue_;

    // The parser is stored in an optional container so we can
    // construct it from scratch it at the beginning of each new message.
    boost::optional<http::request_parser<http::string_body>> parser_;

protected:
    beast::flat_buffer buffer_;
    ApiHandler *api_handler_;
    bool is_ssl_;

public:
    // Construct the session
    http_session(
        beast::flat_buffer buffer,
        std::shared_ptr<std::string const> const& doc_root,
        ApiHandler *api_handler,
        bool is_ssl = false)
        : doc_root_(doc_root)
        , queue_(*this)
        , buffer_(std::move(buffer))
        , api_handler_(api_handler)
        , is_ssl_(is_ssl)
    {
    }

    void do_read()
    {
        // Construct a new parser for each message
        parser_.emplace();

        // Apply a reasonable limit to the allowed size
        // of the body in bytes to prevent abuse.
        parser_->body_limit(SEAL_BLOCK_MAX_SIZE);

        // Set the timeout.
        beast::get_lowest_layer(
            derived().stream()).expires_after(std::chrono::seconds(WEB_TIMEOUT));

        // Read a request using the parser-oriented interface
        http::async_read(
            derived().stream(),
            buffer_,
            *parser_,
            beast::bind_front_handler(
                &http_session::on_read,
                derived().shared_from_this()));
    }

    void on_read(beast::error_code ec, std::size_t bytes_transferred)
    {
        boost::ignore_unused(bytes_transferred);

        // This means they closed the connection
        if(ec == http::error::end_of_stream)
            return derived().do_eof();

        if(ec)
            return fail(ec, "read");

        // See if it is a WebSocket Upgrade
        if(websocket::is_upgrade(parser_->get()))
        {
            // Disable the timeout.
            // The websocket::stream uses its own timeout settings.
            beast::get_lowest_layer(derived().stream()).expires_never();

            // Create a websocket session, transferring ownership
            // of both the socket and the HTTP request.
            return make_websocket_session(
                derived().release_stream(),
                parser_->release(),
                api_handler_);
        }

        // Send the response
        api_handler_->http_handler(*doc_root_, parser_->release(), queue_, is_ssl_);

        // If we aren't at the Queue limit, try to pipeline another request
        if(! queue_.is_full())
            do_read();
    }

    void on_write(bool close, beast::error_code ec, std::size_t bytes_transferred)
    {
        boost::ignore_unused(bytes_transferred);

        if(ec)
            return fail(ec, "write");

        // Clear the buffer
        buffer_.consume(buffer_.size());

        if(close)
        {
            // This means we should close the connection, usually because
            // the response indicated the "Connection: close" semantic.
            return derived().do_eof();
        }

        // Inform the Queue that a write completed
        if(queue_.on_write())
        {
            // Read another request
            do_read();
        }
    }
};

//------------------------------------------------------------------------------

// Handles a plain HTTP connection
class plain_http_session
    : public http_session<plain_http_session>
    , public std::enable_shared_from_this<plain_http_session>
{
    beast::tcp_stream stream_;
    ApiHandler *api_handler_;

public:
    // Create the session
    plain_http_session(
        beast::tcp_stream&& stream,
        beast::flat_buffer&& buffer,
        std::shared_ptr<std::string const> const& doc_root,
        ApiHandler *api_handler)
        : http_session<plain_http_session>(
            std::move(buffer),
            doc_root,
            api_handler)
        , stream_(std::move(stream))
        , api_handler_(api_handler)
    {
    }

    // Start the session
    void run()
    {
        this->do_read();
    }

    // Called by the base class
    beast::tcp_stream& stream()
    {
        return stream_;
    }

    // Called by the base class
    beast::tcp_stream release_stream()
    {
        return std::move(stream_);
    }

    // Called by the base class
    void do_eof()
    {
        // Send a TCP shutdown
        beast::error_code ec;
        stream_.socket().shutdown(tcp::socket::shutdown_send, ec);

        // At this point the connection is closed gracefully
    }
};

//------------------------------------------------------------------------------

// Handles an SSL HTTP connection
class ssl_http_session
    : public http_session<ssl_http_session>
    , public std::enable_shared_from_this<ssl_http_session>
{
    beast::ssl_stream<beast::tcp_stream> stream_;
    ApiHandler *api_handler_;

public:
    // Create the http_session
    ssl_http_session(
        beast::tcp_stream&& stream,
        ssl::context& ctx,
        beast::flat_buffer&& buffer,
        std::shared_ptr<std::string const> const& doc_root,
        ApiHandler *api_handler)
        : http_session<ssl_http_session>(
            std::move(buffer),
            doc_root,
            api_handler,
            true)
        , stream_(std::move(stream), ctx)
        , api_handler_(api_handler)
    {
    }

    // Start the session
    void run()
    {
        // Set the timeout.
        beast::get_lowest_layer(stream_).expires_after(std::chrono::seconds(30));

        // Perform the SSL handshake
        // Note, this is the buffered version of the handshake.
        stream_.async_handshake(
            ssl::stream_base::server,
            buffer_.data(),
            beast::bind_front_handler(
                &ssl_http_session::on_handshake,
                shared_from_this()));
    }

    // Called by the base class
    beast::ssl_stream<beast::tcp_stream>& stream()
    {
        return stream_;
    }

    // Called by the base class
    beast::ssl_stream<beast::tcp_stream> release_stream()
    {
        return std::move(stream_);
    }

    // Called by the base class
    void do_eof()
    {
        // Set the timeout.
        beast::get_lowest_layer(stream_).expires_after(std::chrono::seconds(30));

        // Perform the SSL shutdown
        stream_.async_shutdown(
            beast::bind_front_handler(
                &ssl_http_session::on_shutdown,
                shared_from_this()));
    }

private:
    void on_handshake(
        beast::error_code ec,
        std::size_t bytes_used)
    {
        if(ec)
            return fail(ec, "handshake");

        // Consume the portion of the buffer used by the handshake
        buffer_.consume(bytes_used);

        do_read();
    }

    void on_shutdown(beast::error_code ec)
    {
        if(ec)
            return fail(ec, "shutdown");

        // At this point the connection is closed gracefully
    }
};

//------------------------------------------------------------------------------

// Detects SSL handshakes
class detect_session : public std::enable_shared_from_this<detect_session>
{
    beast::tcp_stream stream_;
    ssl::context& ctx_;
    std::shared_ptr<std::string const> doc_root_;
    beast::flat_buffer buffer_;
    ApiHandler *api_handler_;

public:
    explicit detect_session(
        tcp::socket&& socket,
        ssl::context& ctx,
        std::shared_ptr<std::string const> const& doc_root,
        ApiHandler *api_handler)
        : stream_(std::move(socket))
        , ctx_(ctx)
        , doc_root_(doc_root)
        , api_handler_(api_handler)
    {
    }

    // Launch the detector
    void run()
    {
        // Set the timeout.
        stream_.expires_after(std::chrono::seconds(30));

        beast::async_detect_ssl(
            stream_,
            buffer_,
            beast::bind_front_handler(
                &detect_session::on_detect,
                this->shared_from_this()));
    }

    void on_detect(beast::error_code ec, boost::tribool result)
    {
        if(ec)
            return fail(ec, "detect");

        if(result)
        {
            // Launch SSL session
            std::make_shared<ssl_http_session>(
                std::move(stream_),
                ctx_,
                std::move(buffer_),
                doc_root_,
                api_handler_)->run();
            return;
        }

        // Launch plain session
        std::make_shared<plain_http_session>(
            std::move(stream_),
            std::move(buffer_),
            doc_root_,
            api_handler_)->run();
    }
};


//--------------------------------------------------------------------------
//                              WebServer class
//--------------------------------------------------------------------------

WebServer::WebServer(
    net::io_context& ioc,
    ssl::context& ctx,
    tcp::endpoint endpoint,
    std::shared_ptr<std::string const> const& doc_root)
    : ioc_(ioc)
    , ctx_(ctx)
    , acceptor_(net::make_strand(ioc))
    , doc_root_(doc_root)
{
    beast::error_code ec;

    endpoint_ = endpoint;

    // Open the acceptor
    acceptor_.open(endpoint.protocol(), ec);
    if(ec)
    {
        fail(ec, "open");
        return;
    }

    // Allow address reuse
    acceptor_.set_option(net::socket_base::reuse_address(true), ec);
    if(ec)
    {
        fail(ec, "set_option");
        return;
    }
}

void WebServer::stop()
{
    this->ioc_.stop();
}

// Start accepting incoming connections
bool WebServer::run()
{
    beast::error_code ec;

    // Bind to the server address
    acceptor_.bind(endpoint_, ec);
    if(ec)
    {
        fail(ec, "bind");
        return false;
    }

    // Start listening for connections
    acceptor_.listen(
        net::socket_base::max_listen_connections, ec);
    if(ec)
    {
        fail(ec, "listen");
        return false;
    }

    do_accept();

    return true;
}

void WebServer::do_accept()
{
    // The new connection gets its own strand
    acceptor_.async_accept(
        net::make_strand(ioc_),
        beast::bind_front_handler(
            &WebServer::on_accept,
            shared_from_this()));
}

void WebServer::on_accept(beast::error_code ec, tcp::socket socket)
{
    if(ec)
    {
        fail(ec, "accept");
    }
    else
    {
        // Create the detector http_session and run it
        ApiHandler *api_handler = new ApiHandler();
        std::make_shared<detect_session>(
            std::move(socket),
            ctx_,
            doc_root_,
            api_handler)->run();
    }

    // Accept another connection
    do_accept();
}

void WebServer::set_api_handler(ApiHandler *api_handler)
{
    this->api_handler = api_handler;
}

void stop_webservice(void)
{
    p_ioc->stop();
    kill(g_webservice_pid, SIGINT);
}

void start_webservice(void)
{
    // Check command line arguments.
    Config *p_config = Config::get_instance();
    UrlEndPoint *url_end_point = get_url_end_point(p_config->base_url);
    auto const address = net::ip::make_address(url_end_point->ip);
    auto const port = static_cast<unsigned short>(url_end_point->port);
    auto const doc_root = std::make_shared<std::string>(url_end_point->base);
    auto const threads = std::max<int>(1, WEBSOCKET_THREAD_NUM);

    // The io_context is required for all I/O
    //net::io_context ioc{threads};
    std::shared_ptr<net::io_context> ioc = std::make_shared<net::io_context>(threads);
    p_ioc = ioc;

    // The SSL context is required, and holds certificates
    ssl::context ctx{ssl::context::tlsv12};

    // This holds the self-signed certificate used by the server
    load_server_certificate(ctx);

    // Create and launch a server
    if (! std::make_shared<WebServer>(*ioc, ctx, tcp::endpoint{address, port}, doc_root)->run())
    {
        g_start_server_success = 0;
        return;
    }
    g_start_server_success = 1;

    // Capture SIGINT and SIGTERM to perform a clean shutdown
    //net::signal_set signals(ioc, SIGINT, SIGTERM);
    //signals.async_wait(
    //    [&](beast::error_code const&, int)
    //    {
    //        // Stop the `io_context`. This will cause `run()`
    //        // to return immediately, eventually destroying the
    //        // `io_context` and all of the sockets in it.
    //        ioc.stop();
    //    });

    // Run the I/O service on the requested number of threads
    std::vector<std::thread> v;
    v.reserve(threads - 1);
    for(auto i = threads - 1; i > 0; --i)
    {
        v.emplace_back(
        [&ioc]
        {
            ioc->run();
        });
    }
    ioc->run();

    g_webservice_pid = getpid();

    // (If we get here, it means we got a SIGINT or SIGTERM)
    
    // Block until all the threads exit
    for(auto& t : v)
        t.join();

}
