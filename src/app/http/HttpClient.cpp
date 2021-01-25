#include "HttpClient.h"
#include "Common.h"
#include "Config.h"
#include "Log.h"


namespace beast = boost::beast; // from <boost/beast.hpp>
namespace http = beast::http;   // from <boost/beast/http.hpp>
namespace net = boost::asio;    // from <boost/asio.hpp>
namespace ssl = boost::asio::ssl;       // from <boost/asio/ssl.hpp>
using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>

crust::Log *p_log = crust::Log::get_instance();

// ------------------------------ http request ------------------------------ //

// ---------- http Get ---------- //
http::response<http::string_body> HttpClient::Get(std::string url)
{
    return request_sync(http::verb::get, url, "");
}

http::response<http::string_body> HttpClient::Get(std::string url, std::string body)
{
    return request_sync(http::verb::get, url, body);
}

http::response<http::string_body> HttpClient::Get(std::string url, std::string body, std::string content_type)
{
    return request_sync(http::verb::get, url, body, content_type);
}

http::response<http::string_body> HttpClient::Get(std::string url, std::string body, ApiHeaders &headers)
{
    return request_sync(http::verb::get, url, body, "text/plain", &headers);
}

http::response<http::string_body> HttpClient::Get(std::string url, std::string body, std::string content_type, ApiHeaders &headers)
{
    return request_sync(http::verb::get, url, body, content_type, &headers);
}

// ---------- http Post ---------- //
http::response<http::string_body> HttpClient::Post(std::string url)
{
    return request_sync(http::verb::post, url, "");
}

http::response<http::string_body> HttpClient::Post(std::string url, std::string body)
{
    return request_sync(http::verb::post, url, body);
}

http::response<http::string_body> HttpClient::Post(std::string url, std::string body, std::string content_type)
{
    return request_sync(http::verb::post, url, body, content_type);
}

http::response<http::string_body> HttpClient::Post(std::string url, std::string body, ApiHeaders &headers)
{
    return request_sync(http::verb::post, url, body, "text/plain", &headers);
}

http::response<http::string_body> HttpClient::Post(std::string url, std::string body, std::string content_type, ApiHeaders &headers)
{
    return request_sync(http::verb::post, url, body, content_type, &headers);
}

// ------------------------------ SSL request ------------------------------ //

// ---------- ssl Get ---------- //
http::response<http::string_body> HttpClient::SSLGet(std::string url)
{
    return request_sync_ssl(http::verb::get, url, "");
}

http::response<http::string_body> HttpClient::SSLGet(std::string url, std::string body)
{
    return request_sync_ssl(http::verb::get, url, body);
}

http::response<http::string_body> HttpClient::SSLGet(std::string url, std::string body, std::string content_type)
{
    return request_sync_ssl(http::verb::get, url, body, content_type);
}

http::response<http::string_body> HttpClient::SSLGet(std::string url, std::string body, ApiHeaders &headers)
{
    return request_sync_ssl(http::verb::get, url, body, "text/plain", &headers);
}

http::response<http::string_body> HttpClient::SSLGet(std::string url, std::string body, std::string content_type, ApiHeaders &headers)
{
    return request_sync_ssl(http::verb::get, url, body, content_type, &headers);
}

// ---------- ssl Post ---------- //
http::response<http::string_body> HttpClient::SSLPost(std::string url)
{
    return request_sync_ssl(http::verb::post, url, "");
}

http::response<http::string_body> HttpClient::SSLPost(std::string url, std::string body)
{
    return request_sync_ssl(http::verb::post, url, body);
}

http::response<http::string_body> HttpClient::SSLPost(std::string url, std::string body, request_type_t type)
{
    return request_sync_ssl(http::verb::post, url, body, "text/plain", NULL, type);
}

http::response<http::string_body> HttpClient::SSLPost(std::string url, std::string body, std::string content_type)
{
    return request_sync_ssl(http::verb::post, url, body, content_type);
}

http::response<http::string_body> HttpClient::SSLPost(std::string url, std::string body, std::string content_type, request_type_t type)
{
    return request_sync_ssl(http::verb::post, url, body, content_type, NULL, type);
}

http::response<http::string_body> HttpClient::SSLPost(std::string url, std::string body, ApiHeaders &headers)
{
    return request_sync_ssl(http::verb::post, url, body, "text/plain", &headers);
}

http::response<http::string_body> HttpClient::SSLPost(std::string url, std::string body, ApiHeaders &headers, request_type_t type)
{
    return request_sync_ssl(http::verb::post, url, body, "text/plain", &headers, type);
}

http::response<http::string_body> HttpClient::SSLPost(std::string url, std::string body, std::string content_type, ApiHeaders &headers)
{
    return request_sync_ssl(http::verb::post, url, body, content_type, &headers);
}

http::response<http::string_body> HttpClient::SSLPost(std::string url, std::string body, std::string content_type, ApiHeaders &headers, request_type_t type)
{
    return request_sync_ssl(http::verb::post, url, body, content_type, &headers, type);
}


/**
 * @description: Performs an SSL request and prints the response
 * @param method -> Head, Get or Post
 * @param url -> Request url
 * @param body -> Request body
 * @param content_type -> Indicates content type
 * @param headers -> Poniter to header
 * @return: Json result
 */
http::response<http::string_body> HttpClient::request_sync_ssl(http::verb method, std::string url, 
        std::string body,std::string content_type, ApiHeaders *headers, request_type_t type)
{
    // Declare a container to hold the response
    http::response<http::string_body> res;

    try
    {
        UrlEndPoint url_end_point = get_url_end_point(url);
        auto const host = url_end_point.ip.c_str();
        auto port = std::to_string(url_end_point.port).c_str();
        auto const path = url_end_point.base.c_str();
        int version = 10;
        if (std::strncmp(port, "-1", 2) == 0)
        {
            port = "443";
        }
        //int version = argc == 5 && !std::strcmp("1.0", argv[4]) ? 10 : 11;

        // The io_context is required for all I/O
        net::io_context ioc;

        // These objects perform our I/O
        tcp::resolver resolver(ioc);

        // The SSL context is required, and holds certificates
        ssl::context ctx(ssl::context::tlsv12_client);
        //ssl::context ctx(ssl::context::sslv23);
        ctx.set_default_verify_paths();

        // This holds the root certificate used for verification
        //ctx = SSL_CTX_new(SSLv23_client_method());
        //load_root_certificates_http(ctx);

        // Verify the remote server's certificate
        if (HTTP_REQ_SECURE == type)
        {
            ctx.set_verify_mode(ssl::verify_peer);
        }
        beast::ssl_stream<beast::tcp_stream> stream(ioc, ctx);

        // Set SNI Hostname (many hosts need this to handshake successfully)
        if(! SSL_set_tlsext_host_name(stream.native_handle(), const_cast<char*>(host)))
        {
            beast::error_code ec{static_cast<int>(::ERR_get_error()), net::error::get_ssl_category()};
            throw beast::system_error{ec};
        }

        // Look up the domain name
        auto const results = resolver.resolve(host, port);

        // Make the connection on the IP address we get from a lookup
        beast::get_lowest_layer(stream).connect(results);

        // Perform the SSL handshake
        stream.handshake(ssl::stream_base::client);

        // Set up an HTTP GET request message
        http::request<http::string_body> req{method, path, version};
        req.set(http::field::host, host);
        req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
        req.set(http::field::content_type, content_type);
        req.set(http::field::content_length, body.size());
        // Set header
        if (headers != NULL)
        {
            for (auto entry = headers->begin(); entry != headers->end(); entry++)
            {
                req.set(entry->first, entry->second);
            }
        }
        // Set body
        req.body() = body;

        // Send the HTTP request to the remote host
        http::write(stream, req);

        // This buffer is used for reading and must be persisted
        beast::flat_buffer buffer;

        // Receive the HTTP response
        http::response_parser<http::string_body> parser;
        parser.body_limit(HTTP_RECV_BODY_LIMIT);
        http::read(stream, buffer, parser);
        res = parser.get();

        // Gracefully close the stream
        beast::error_code ec;
        beast::get_lowest_layer(stream).close();
        //stream.shutdown(ec);
        if(ec == net::error::eof)
        {
            // Rationale:
            // http://stackoverflow.com/questions/25587403/boost-asio-ssl-async-shutdown-always-finishes-with-an-error
            ec = {};
        }
        if(ec)
            throw beast::system_error{ec};

        // If we get here then the connection is closed gracefully
    }
    catch(std::exception const& e)
    {
        p_log->debug("Http request error: %s\n", e.what());
        res.result(404);
        return res;
    }
    return res;
}

/**
 * @description: Performs an HTTP request and prints the response
 * @param method -> Head, Get or Post
 * @param url -> Request url
 * @param body -> Request body
 * @param content_type -> Indicates content type
 * @param headers -> Poniter to header
 * @return: Json result
 */
http::response<http::string_body> HttpClient::request_sync(http::verb method, std::string url, 
        std::string body, std::string content_type, ApiHeaders *headers)
{
    // Declare a container to hold the response
    http::response<http::string_body> res;

    try
    {
        UrlEndPoint url_end_point = get_url_end_point(url);
        auto const host = url_end_point.ip.c_str();
        auto const port = std::to_string(url_end_point.port).c_str();
        auto const path = url_end_point.base.c_str();
        int version = 10;

        // The io_context is required for all I/O
        net::io_context ioc;

        // These objects perform our I/O
        tcp::resolver resolver(ioc);
        beast::tcp_stream stream(ioc);

        // Look up the domain name
        auto const results = resolver.resolve(host, port);

        // Make the connection on the IP address we get from a lookup
        stream.connect(results);

        // Set up an HTTP GET request message
        http::request<http::string_body> req{method, path, version};
        req.set(http::field::host, host);
        req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
        req.set(http::field::content_type, content_type);
        req.set(http::field::content_length, body.size());
        // Set header
        if (headers != NULL)
        {
            for (auto entry = headers->begin(); entry != headers->end(); entry++)
            {
                req.set(entry->first, entry->second);
            }
        }
        // Set body
        req.body() = body;

        // Send the HTTP request to the remote host
        http::write(stream, req);

        // This buffer is used for reading and must be persisted
        beast::flat_buffer buffer;

        // Receive the HTTP response
        http::response_parser<http::string_body> parser;
        parser.body_limit(HTTP_RECV_BODY_LIMIT);
        http::read(stream, buffer, parser);
        res = parser.get();

        // Gracefully close the socket
        beast::error_code ec;
        stream.socket().shutdown(tcp::socket::shutdown_both, ec);

        // not_connected happens sometimes
        // so don't bother reporting it.
        //
        if(ec && ec != beast::errc::not_connected)
            throw beast::system_error{ec};

        // If we get here then the connection is closed gracefully
    }
    catch(std::exception const& e)
    {
        p_log->debug("Http request error: %s\n", e.what());
        res.result(404);
        return res;
    }
    return res;
}
