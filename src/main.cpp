#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/error.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/version.hpp>
#include <boost/program_options.hpp>
#include <boost/url.hpp>
#include <cstdlib>
#include <iostream>
#include <string>

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
namespace ssl = net::ssl;
using tcp = net::ip::tcp;
namespace urls = boost::urls;
namespace po = boost::program_options;

int main(int argc, char** argv) {
    po::options_description desc("Allowed options");

    // clang-format off
    desc.add_options()
        ("help,h", "print help info")
        ("url,u", po::value<std::string>(), "url that needs to be shortened")
        ("scheme,s", po::value<std::string>()->default_value("https"),
         "which scheme set if it is missing in the url")
        ("provider,p", po::value<std::string>()->default_value("clck.ru"),
         "url of the clck link shortener")
    ;
    // clang-format on

    po::positional_options_description p;
    p.add("url", -1);

    try {
        po::variables_map vm;
        po::store(po::command_line_parser(argc, argv)
                      .options(desc)
                      .positional(p)
                      .run(),
                  vm);
        po::notify(vm);

        if (vm.count("help") || argc <= 1) {
            std::cout << desc << "\n";
            return EXIT_SUCCESS;
        }

        urls::url long_url(vm["url"].as<std::string>());
        if (!long_url.has_scheme()) {
            long_url = urls::url(vm["scheme"].as<std::string>() + "://" +
                                 std::string(long_url.buffer()));
        }

        urls::url url;
        url.set_scheme("https");
        url.set_host(vm["provider"].as<std::string>());
        url.set_path("--");
        url.set_query("url=" + urls::encode(long_url, urls::pchars));
        const std::string host = url.host();
        const auto scheme = url.scheme();
        const char* port = scheme == "https" ? "443" : "80";
        const auto target = url.path() + "?" + url.query();
        const int version = 11;

        net::io_context ioc;
        ssl::context ctx(ssl::context::tlsv12_client);

        tcp::resolver resolver(ioc);
        beast::ssl_stream<beast::tcp_stream> stream(ioc, ctx);

        if (!SSL_set_tlsext_host_name(stream.native_handle(), host.c_str())) {
            beast::error_code ec{static_cast<int>(::ERR_get_error()),
                                 net::error::get_ssl_category()};
            throw beast::system_error{ec};
        }

        auto const results = resolver.resolve(host, port);

        beast::get_lowest_layer(stream).connect(results);

        stream.handshake(ssl::stream_base::client);

        http::request<http::string_body> req{http::verb::get, target, version};
        req.set(http::field::host, host);
        req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);

        http::write(stream, req);

        beast::flat_buffer buffer;

        http::response<http::string_body> res;

        http::read(stream, buffer, res);

        if (res.result() != http::status::ok) {
            std::cerr << "API error:" << std::endl;
            std::cerr << res.body() << std::endl;
            return EXIT_FAILURE;
        }

        std::cout << res.body() << std::endl;

        beast::error_code ec;
        stream.shutdown(ec);
        if (ec == net::error::eof) {
            ec = {};
        }
        if (ec) {
            throw beast::system_error{ec};
        }

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
