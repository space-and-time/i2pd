#include "sslclient.h"
#include "Log.h"


SSLClient::SSLClient(boost::asio::io_service& io_service,
      boost::asio::ssl::context& context,
      boost::asio::ip::tcp::resolver::iterator endpoint_iterator, char request[max_length])
        : m_socket(io_service, context), m_request(request)
{
  m_socket.set_verify_mode(boost::asio::ssl::verify_peer);
  m_socket.set_verify_callback(boost::bind(&SSLClient::verify_certificate, this, _1, _2));
  boost::asio::async_connect(m_socket.lowest_layer(), endpoint_iterator,
      boost::bind(&SSLClient::handle_connect, this, boost::asio::placeholders::error));
}

bool SSLClient::verify_certificate(bool preverified, boost::asio::ssl::verify_context& ctx)
{
  //TODO: Check certificate better
  char subject_name[256];
  X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
  X509_NAME_oneline(X509_get_subject_name(cert), subject_name, 256);
  LogPrint("SSL Verifiying ", subject_name);
  return preverified;
}

void SSLClient::handle_connect(const boost::system::error_code& error)
{
  if (!error)
  {
    m_socket.async_handshake(boost::asio::ssl::stream_base::client,
       boost::bind(&SSLClient::handle_handshake, this, boost::asio::placeholders::error));
  }
  else
  {
      LogPrint("SSL Connect failed: ", error.message());
  }
}


void SSLClient::handle_handshake(const boost::system::error_code& error)
{
  if (!error)
  {
    size_t request_length = strlen(m_request);

    boost::asio::async_write(m_socket,
        boost::asio::buffer(m_request, request_length),
        boost::bind(&SSLClient::handle_write, this,
          boost::asio::placeholders::error,
          boost::asio::placeholders::bytes_transferred));
  }
  else
  {
      LogPrint("SSL Handshake failed: ", error.message());
  }
}


void SSLClient::handle_write(const boost::system::error_code& error, size_t bytes_transferred)
{
  if (!error)
  {
    boost::asio::async_read(m_socket, boost::asio::buffer(m_reply, bytes_transferred),
      boost::bind(&SSLClient::handle_read, this, boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));
  }
  else
  {
    LogPrint("SSL Write failed: ", error.message());
  }
}

void SSLClient::handle_read(const boost::system::error_code& error, size_t bytes_transferred)
{
  if (!error)
  {
    LogPrint("SSL Read success");
  }
  else
  {
    LogPrint("SSL Read failed: ", error.message());
  }
}



