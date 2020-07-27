#include "WebsocketClient.h"
#include "Log.h"

namespace beast = boost::beast; // from <boost/beast.hpp>
namespace http = beast::http;   // from <boost/beast/http.hpp>
namespace websocket = beast::websocket;
namespace net = boost::asio;    // from <boost/asio.hpp>
namespace ssl = boost::asio::ssl;       // from <boost/asio/ssl.hpp>
using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>

crust::Log *p_log = crust::Log::get_instance();

// Report a failure
void fail(beast::error_code ec, char const* what)
{
    if(ec == net::ssl::error::stream_truncated)
        return;

    p_log->err("Webserver error: ");
    std::cerr << what << ": " << ec.message() << "\n";
}

/**
 * @description: Initialize websocket
 * @param host -> Host name or ip address
 * @param port -> Server port
 * @param route -> Request route path
 * @return: Initialize status
 */
bool WebsocketClient::websocket_init(std::string host, std::string port, std::string route)
{
    try
    {
        // The io_context is required for all I/O
        //net::io_context ioc;
        this->_ioc = std::make_shared<net::io_context>();

        // The SSL context is required, and holds certificates
        ssl::context ctx{ssl::context::tlsv12_client};

        // This holds the root certificate used for verification
        load_root_certificates(ctx);

        // These objects perform our I/O
        //tcp::resolver resolver{ioc};
        this->_resolver = std::make_shared<tcp::resolver>(*this->_ioc);
        //websocket::stream<beast::ssl_stream<tcp::socket>> ws{ioc, ctx};
        //websocket::stream<tcp::socket> ws{ioc};
        this->_ws = std::make_shared<websocket::stream<tcp::socket>>(*this->_ioc);

        // Look up the domain name
        auto const results = this->_resolver->resolve(host, port);

        // Make the connection on the IP address we get from a lookup
        //net::connect(ws.next_layer().next_layer(), results.begin(), results.end());
        //net::connect(ws.next_layer(), results.begin(), results.end());
        net::connect(this->_ws->next_layer(), results.begin(), results.end());

        // Perform the SSL handshake
        //ws.next_layer().handshake(ssl::stream_base::client);

        // Set a decorator to change the User-Agent of the handshake
        this->_ws->set_option(websocket::stream_base::decorator(
            [](websocket::request_type& req)
            {
                req.set(http::field::user_agent,
                    std::string(BOOST_BEAST_VERSION_STRING) +
                        " websocket-client-coro");
            }));

        // Perform the websocket handshake
        this->_ws->handshake(host, route);
    }
    catch(std::exception const& e)
    {
        p_log->debug("Initialize websocket client failed! Error: %s\n", e.what());
        this->_ws = NULL;
        return false;
    }

    return true;
}

/**
 * @description: Send request content to server
 * @param content -> Request content
 * @param res -> Response from server
 * @return: Request status
 */
bool WebsocketClient::websocket_request(std::string content, std::string &res)
{
    if (this->_ws == NULL)
    {
        p_log->debug("Websocket request failed! Please initialize websocket first!\n");
        return false;
    }

    try
    {
        // Send the message
        this->_ws->write(net::buffer(content));

        // This buffer will hold the incoming message
        beast::flat_buffer buffer;

        // Read a message into our buffer
        this->_ws->read(buffer);

        res = beast::buffers_to_string(buffer.data());
    }
    catch(std::exception const& e)
    {
        p_log->debug("Send websocket request failed! Error: %s\n", e.what());
        return false;
    }

    return true;
}

/**
 * @description: Close websocket
 */
void WebsocketClient::websocket_close()
{
    // Close the WebSocket connection
    if (this->_ws != NULL)
    {
        beast::error_code ec;
        this->_ws->close(websocket::close_code::normal, ec);
        if (ec)
            fail(ec, "close");
        this->_ws = NULL;
    }
}
