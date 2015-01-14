#ifndef I2P_CONTROL_H__
#define I2P_CONTROL_H__

#include <inttypes.h>
#include <thread>
#include <memory>
#include <array>
#include <string>
#include <map>
#include <boost/asio.hpp>

namespace i2p
{
namespace client
{
	const size_t I2P_CONTROL_MAX_REQUEST_SIZE = 1024;
	typedef std::array<char, I2P_CONTROL_MAX_REQUEST_SIZE> I2PControlBuffer;		

	const char I2P_CONTROL_PROPERTY_ID[] = "id";
	const char I2P_CONTROL_PROPERTY_METHOD[] = "method";
	const char I2P_CONTROL_PROPERTY_PARAMS[] = "params";
	const char I2P_CONTROL_PROPERTY_RESULT[] = "result";

	// methods	
	const char I2P_CONTROL_METHOD_AUTHENTICATE[] = "Authenticate";
	const char I2P_CONTROL_METHOD_ECHO[] = "Echo";		
	const char I2P_CONTROL_METHOD_ROUTER_INFO[] = "RouterInfo";	
	const char I2P_CONTROL_METHOD_ROUTER_MANAGER[] = "RouterManager";	
	const char I2P_CONTROL_METHOD_NETWORK_SETTING[] = "NetworkSetting";	

	// params
	const char I2P_CONTROL_PARAM_API[] = "API";			
	const char I2P_CONTROL_PARAM_PASSWORD[] = "Password";	
	const char I2P_CONTROL_PARAM_TOKEN[] = "Token";	
	const char I2P_CONTROL_PARAM_ECHO[] = "Echo";	
	const char I2P_CONTROL_PARAM_RESULT[] = "Result";	

	// RouterInfo requests
	const char I2P_CONTROL_ROUTER_INFO_NETDB_KNOWNPEERS[] = "i2p.router.netdb.knownpeers";
	const char I2P_CONTROL_ROUTER_INFO_TUNNELS_PARTICIPATING[] = "i2p.router.net.tunnels.participating";	
		
	// RouterManager requests
	const char I2P_CONTROL_ROUTER_MANAGER_SHUTDOWN[] = "Shutdown";
	const char I2P_CONTROL_ROUTER_MANAGER_SHUTDOWN_GRACEFUL[] = "ShutdownGraceful";
	
	class I2PControlService
	{
		public:

			I2PControlService (int port);
			~I2PControlService ();

			void Start ();
			void Stop ();

		private:

			void Run ();
			void Accept ();
			void HandleAccept(const boost::system::error_code& ecode, std::shared_ptr<boost::asio::ip::tcp::socket> socket);	
			void ReadRequest (std::shared_ptr<boost::asio::ip::tcp::socket> socket);
			void HandleRequestReceived (const boost::system::error_code& ecode, size_t bytes_transferred, 
				std::shared_ptr<boost::asio::ip::tcp::socket> socket, std::shared_ptr<I2PControlBuffer> buf);
			void SendResponse (std::shared_ptr<boost::asio::ip::tcp::socket> socket,
				std::shared_ptr<I2PControlBuffer> buf, const std::string& id, 
				const std::map<std::string, std::string>& results);
			void HandleResponseSent (const boost::system::error_code& ecode, std::size_t bytes_transferred,
				std::shared_ptr<boost::asio::ip::tcp::socket> socket, std::shared_ptr<I2PControlBuffer> buf);

		private:

			// methods
			typedef void (I2PControlService::*MethodHandler)(const std::map<std::string, std::string>& params, std::map<std::string, std::string>& results);

			void AuthenticateHandler (const std::map<std::string, std::string>& params, std::map<std::string, std::string>& results);
			void EchoHandler (const std::map<std::string, std::string>& params, std::map<std::string, std::string>& results);
			void RouterInfoHandler (const std::map<std::string, std::string>& params, std::map<std::string, std::string>& results);
			void RouterManagerHandler (const std::map<std::string, std::string>& params, std::map<std::string, std::string>& results);
			void NetworkSettingHandler (const std::map<std::string, std::string>& params, std::map<std::string, std::string>& results);			

			// RouterInfo
			typedef void (I2PControlService::*RouterInfoRequestHandler)(std::map<std::string, std::string>& results);
			void NetDbKnownPeersHandler (std::map<std::string, std::string>& results);			
			void TunnelsParticipatingHandler (std::map<std::string, std::string>& results);

			// RouterManager
			typedef void (I2PControlService::*RouterManagerRequestHandler)(std::map<std::string, std::string>& results);
			void ShutdownHandler (std::map<std::string, std::string>& results);
			void ShutdownGracefulHandler (std::map<std::string, std::string>& results);

			// NetworkSetting
			typedef void (I2PControlService::*NetworkSettingRequestHandler)(const std::string& value, std::map<std::string, std::string>& results);	

		private:

			bool m_IsRunning;
			std::thread * m_Thread;	

			boost::asio::io_service m_Service;
			boost::asio::ip::tcp::acceptor m_Acceptor;
			boost::asio::deadline_timer m_ShutdownTimer;
			
			std::map<std::string, MethodHandler> m_MethodHandlers;
			std::map<std::string, RouterInfoRequestHandler> m_RouterInfoHandlers;
			std::map<std::string, RouterManagerRequestHandler> m_RouterManagerHandlers;
			std::map<std::string, NetworkSettingRequestHandler> m_NetworkSettingHandlers;
	};
}
}

#endif

