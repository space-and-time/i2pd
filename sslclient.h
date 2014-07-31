#ifndef __SSLCLIENT_H__
#define __SSLCLIENT_H__

#include <boost/bind.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

enum { max_length = 1024 };

class SSLClient {
  public:
    SSLClient(boost::asio::io_service& io_service, boost::asio::ssl::context& context, boost::asio::ip::tcp::resolver::iterator endpoint_iterator, char request[max_length]);
    bool verify_certificate(bool preverified, boost::asio::ssl::verify_context& ctx);
    void handle_connect(const boost::system::error_code& error);
    void handle_handshake(const boost::system::error_code& error);
    void handle_write(const boost::system::error_code& error, size_t bytes_transferred);
    void handle_read(const boost::system::error_code& error, size_t bytes_transferred);
  private:
    boost::asio::ssl::stream<boost::asio::ip::tcp::socket> m_socket;
    char m_request[max_length];
    char m_reply[max_length];
};


#endif
