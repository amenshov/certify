#ifndef BOOST_CERTIFY_IMPL_EXTENSIONS_HPP
#define BOOST_CERTIFY_IMPL_EXTENSIONS_HPP

#include <boost/certify/extensions.hpp>

namespace boost
{
namespace certify
{

template<class AsyncStream>
string_view
sni_hostname(asio::ssl::stream<AsyncStream> const& stream)
{
    auto handle =
      const_cast<asio::ssl::stream<AsyncStream>&>(stream).native_handle();
    auto* hostname = SSL_get_servername(handle, TLSEXT_NAMETYPE_host_name);
    if (hostname == nullptr)
        return string_view{};
    return {hostname};
}

inline void
sni_hostname(::SSL* handle,
             std::string const& hostname,
             system::error_code& ec)
{
    auto ret =
      SSL_set_tlsext_host_name(handle, hostname.c_str());
    if (ret == 0)
        ec = {static_cast<int>(::ERR_get_error()),
              asio::error::get_ssl_category()};
    else
        ec = {};
}

template<class AsyncStream>
void
sni_hostname(asio::ssl::stream<AsyncStream>& stream,
             std::string const& hostname,
             system::error_code& ec)
{
    sni_hostname(stream.native_handle(), hostname, ec);
}

template<class AsyncStream>
void
sni_hostname(asio::ssl::stream<AsyncStream>& stream,
             std::string const& hostname)
{
    system::error_code ec;
    sni_hostname(stream, hostname, ec);
    if (ec)
        boost::throw_exception(system::system_error{ec});
}

template<class AsyncStream>
void
sni_hostname(beast::ssl_stream<AsyncStream>& stream,
             std::string const& hostname,
             system::error_code& ec)
{
    sni_hostname(stream.native_handle(), hostname, ec);
}

template<class AsyncStream>
void
sni_hostname(beast::ssl_stream<AsyncStream>& stream,
             std::string const& hostname)
{
    system::error_code ec;
    sni_hostname(stream, hostname, ec);
    if (ec)
        boost::throw_exception(system::system_error{ec});
}

} // namespace certify
} // namespace boost

#endif // BOOST_CERTIFY_IMPL_EXTENSIONS_HPP
