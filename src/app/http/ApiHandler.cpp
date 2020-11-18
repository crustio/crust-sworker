#include "ApiHandler.h"
#include "sgx_tseal.h"
#include <exception>

namespace beast = boost::beast;         // from <boost/beast.hpp>
namespace http = beast::http;           // from <boost/beast/http.hpp>
namespace websocket = beast::websocket; // from <boost/beast/websocket.hpp>
namespace net = boost::asio;            // from <boost/asio.hpp>
namespace ssl = boost::asio::ssl;       // from <boost/asio/ssl.hpp>
using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>


extern sgx_enclave_id_t global_eid;

crust::Log *p_log = crust::Log::get_instance();

/**
 * @description: Append an HTTP rel-path to a local filesystem path.
 *  The returned path is normalized for the platform.
 * @param base -> Url base path
 * @param path -> Url specific path
 * @return: Analyzed path
 */
std::string path_cat(beast::string_view base, beast::string_view path)
{
    if(base.empty())
        return std::string(path);
    std::string result(base);
#ifdef BOOST_MSVC
    char constexpr path_separator = '\\';
    if(result.back() == path_separator)
        result.resize(result.size() - 1);
    result.append(path.data(), path.size());
    for(auto& c : result)
        if(c == '/')
            c = path_separator;
#else
    char constexpr path_separator = '/';
    if(result.back() == path_separator)
        result.resize(result.size() - 1);
    result.append(path.data(), path.size());
#endif
    return result;
}

/**
 * @description: Get url parameters
 * @param url -> Request URL
 * @return: Key value pair url parameters
 */
std::map<std::string, std::string> get_params(std::string &url)
{
    std::map<std::string, std::string> ans;
    size_t spos = url.find('\?');
    size_t epos;
    if (spos == std::string::npos)
    {
        return ans;
    }
    spos++;
    while (spos < url.size())
    {
        epos = url.find('&', spos);
        if (epos == std::string::npos)
        {
            epos = url.size();
        }
        size_t ppos = url.find('=', spos);
        if (ppos > epos || ppos == std::string::npos)
        {
            return ans;
        }
        std::string key = url.substr(spos, ppos - spos);
        ppos++;
        std::string val = url.substr(ppos, epos - ppos);
        ans[key] = val;

        spos = epos + 1;
    }

    return ans;
}

/**
 * @description: Handle websocket request
 * @param path -> Request path
 * @param data -> Request data
 * @param close_connection -> Indicate whether to close connection
 * @return: Response data as json format
 */
std::string ApiHandler::websocket_handler(std::string &/*path*/, std::string &/*data*/, bool &/*close_connection*/)
{
    //Config *p_config = Config::get_instance();
    json::JSON res;
    //UrlEndPoint *url_end_point = get_url_end_point(p_config->base_url);
    res["status"] = 300;
    res["body"] = "Websocket doesn't provide service now!";

    return res.dump();
}
