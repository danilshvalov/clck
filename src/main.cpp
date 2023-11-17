#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/error.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/version.hpp>
#include <boost/url.hpp>
#include <boost/url/scheme.hpp>

#include <CLI/CLI.hpp>

#include <iostream>
#include <string>

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
namespace ssl = net::ssl;
using tcp = net::ip::tcp;
namespace urls = boost::urls;

std::ostream& operator<<(std::ostream& out, urls::scheme scheme) {
    return out << urls::to_string(scheme);
}

struct SchemeValidator : public CLI::Validator {
   public:
    SchemeValidator() {
        name_ = "SCHEME";
        func_ = [](const std::string& str) -> std::string {
            if (urls::string_to_scheme(str) == urls::scheme::unknown) {
                return "Scheme '" + str + "' is not one of the options: " +
                       make_avaliable_options();
            }
            return "";
        };
        desc_function_ = []() -> std::string {
            return make_avaliable_options();
        };
        non_modifying_ = true;
    }

   private:
    static std::string make_avaliable_options() {
        const int begin = static_cast<int>(urls::scheme::ftp);
        const int end = static_cast<int>(urls::scheme::wss);

        std::string result = "{";
        for (int i = begin; i <= end; ++i) {
            if (i != begin) {
                result += ",";
            }
            result += urls::to_string(static_cast<urls::scheme>(i));
        }
        result += "}";

        return result;
    }
};
const static SchemeValidator Scheme;

int main(int argc, char** argv) {
    CLI::App app{"clck — CLI for the link shortener clck.ru"};
    app.get_formatter()->column_width(59);

    std::vector<std::string> urls;
    std::string scheme;
    std::string provider;

    app.add_option("url", urls, "URL that needs to be shortened")->required();

    app.add_option("-s,--scheme", scheme, "Which scheme set if it is missing")
        ->type_name("SCHEME")
        ->default_val("https")
        ->check(Scheme);

    app.add_option("-r,--remote", provider, "URL of the clck link shortener")
        ->default_val("clck.ru");

    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError& e) {
        return app.exit(e);
    }

    for (std::string long_url_raw : urls) {
        try {
            urls::url long_url(long_url_raw);
            if (!long_url.has_scheme()) {
                long_url =
                    urls::url(scheme + "://" + std::string(long_url.buffer()));
            }

            urls::url url;
            url.set_scheme("https");
            url.set_host(provider);
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

            if (!SSL_set_tlsext_host_name(stream.native_handle(),
                                          host.c_str())) {
                beast::error_code ec{static_cast<int>(::ERR_get_error()),
                                     net::error::get_ssl_category()};
                throw beast::system_error{ec};
            }

            auto const results = resolver.resolve(host, port);

            beast::get_lowest_layer(stream).connect(results);

            stream.handshake(ssl::stream_base::client);

            http::request<http::string_body> req{http::verb::get, target,
                                                 version};
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
        }
    }
}
