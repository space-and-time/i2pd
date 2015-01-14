#include <cryptopp/dh.h>
#include <boost/bind.hpp>
#include "Log.h"
#include "CryptoConst.h"
#include "RouterContext.h"
#include "I2NPProtocol.h"
#include "NetDb.h"
#include "Transports.h"

using namespace i2p::data;

namespace i2p
{
namespace transport
{
	DHKeysPairSupplier::DHKeysPairSupplier (int size):
		m_QueueSize (size), m_IsRunning (false), m_Thread (nullptr)
	{
	}	

	DHKeysPairSupplier::~DHKeysPairSupplier ()
	{
		Stop ();
	}

	void DHKeysPairSupplier::Start ()
	{
		m_IsRunning = true;
		m_Thread = new std::thread (std::bind (&DHKeysPairSupplier::Run, this));
	}

	void DHKeysPairSupplier::Stop ()
	{
		m_IsRunning = false;
		m_Acquired.notify_one ();	
		if (m_Thread)
		{	
			m_Thread->join (); 
			delete m_Thread;
			m_Thread = 0;
		}	
	}

	void DHKeysPairSupplier::Run ()
	{
		while (m_IsRunning)
		{
			int num;
			while ((num = m_QueueSize - m_Queue.size ()) > 0)
				CreateDHKeysPairs (num);
			std::unique_lock<std::mutex>  l(m_AcquiredMutex);
			m_Acquired.wait (l); // wait for element gets aquired
		}
	}		

	void DHKeysPairSupplier::CreateDHKeysPairs (int num)
	{
		if (num > 0)
		{
			CryptoPP::DH dh (i2p::crypto::elgp, i2p::crypto::elgg);
			for (int i = 0; i < num; i++)
			{
				i2p::transport::DHKeysPair * pair = new i2p::transport::DHKeysPair ();
				dh.GenerateKeyPair(m_Rnd, pair->privateKey, pair->publicKey);
				std::unique_lock<std::mutex>  l(m_AcquiredMutex);
				m_Queue.push (pair);
			}
		}
	}

	DHKeysPair * DHKeysPairSupplier::Acquire ()
	{
		if (!m_Queue.empty ())
		{
			std::unique_lock<std::mutex>  l(m_AcquiredMutex);
			auto pair = m_Queue.front ();
			m_Queue.pop ();
			m_Acquired.notify_one ();
			return pair;
		}	
		else // queue is empty, create new
		{
			DHKeysPair * pair = new DHKeysPair ();
			CryptoPP::DH dh (i2p::crypto::elgp, i2p::crypto::elgg);
			dh.GenerateKeyPair(m_Rnd, pair->privateKey, pair->publicKey);
			return pair;
		}
	}

	void DHKeysPairSupplier::Return (DHKeysPair * pair)
	{
		std::unique_lock<std::mutex>  l(m_AcquiredMutex);
		m_Queue.push (pair);
	}

	Transports transports;	
	
	Transports::Transports (): 
		m_IsRunning (false), m_Thread (nullptr), m_Work (m_Service), 
		m_NTCPServer (nullptr), m_SSUServer (nullptr), 
		m_DHKeysPairSupplier (5) // 5 pre-generated keys
	{		
	}
		
	Transports::~Transports () 
	{ 
		Stop ();
	}	

	void Transports::Start ()
	{
		m_DHKeysPairSupplier.Start ();
		m_IsRunning = true;
		m_Thread = new std::thread (std::bind (&Transports::Run, this));
		// create acceptors
		auto addresses = context.GetRouterInfo ().GetAddresses ();
		for (auto& address : addresses)
		{
			if (!m_NTCPServer)
			{	
				m_NTCPServer = new NTCPServer (address.port);
				m_NTCPServer->Start ();
			}	
			
			if (address.transportStyle == RouterInfo::eTransportSSU && address.host.is_v4 ())
			{
				if (!m_SSUServer)
				{	
					m_SSUServer = new SSUServer (address.port);
					LogPrint ("Start listening UDP port ", address.port);
					m_SSUServer->Start ();	
					DetectExternalIP ();
				}
				else
					LogPrint ("SSU server already exists");
			}
		}	
	}
		
	void Transports::Stop ()
	{	
		m_Peers.clear ();
		if (m_SSUServer)
		{
			m_SSUServer->Stop ();
			delete m_SSUServer;
			m_SSUServer = nullptr;
		}	
		if (m_NTCPServer)
		{
			m_NTCPServer->Stop ();
			delete m_NTCPServer;
			m_NTCPServer = nullptr;
		}	

		m_DHKeysPairSupplier.Stop ();
		m_IsRunning = false;
		m_Service.stop ();
		if (m_Thread)
		{	
			m_Thread->join (); 
			delete m_Thread;
			m_Thread = nullptr;
		}	
	}	

	void Transports::Run () 
	{ 
		while (m_IsRunning)
		{
			try
			{	
				m_Service.run ();
			}
			catch (std::exception& ex)
			{
				LogPrint ("Transports: ", ex.what ());
			}	
		}	
	}
		

	void Transports::SendMessage (const i2p::data::IdentHash& ident, i2p::I2NPMessage * msg)
	{
		m_Service.post (boost::bind (&Transports::PostMessage, this, ident, msg));                             
	}	

	void Transports::PostMessage (const i2p::data::IdentHash& ident, i2p::I2NPMessage * msg)
	{
		if (ident == i2p::context.GetRouterInfo ().GetIdentHash ())
		{	
			// we send it to ourself
			i2p::HandleI2NPMessage (msg);
			return;
		}	

		auto it = m_Peers.find (ident);
		if (it == m_Peers.end ())
		{
			auto r = netdb.FindRouter (ident);
			it = m_Peers.insert (std::pair<i2p::data::IdentHash, Peer>(ident, { 0, r, nullptr})).first;
			if (!ConnectToPeer (ident, it->second))
			{
				DeleteI2NPMessage (msg);
				return;
			}	
		}	
		if (it->second.session)
			it->second.session->SendI2NPMessage (msg);
		else
			it->second.delayedMessages.push_back (msg);
	}	

	bool Transports::ConnectToPeer (const i2p::data::IdentHash& ident, Peer& peer)
	{
		if (peer.router) // we have RI already
		{	
			if (!peer.numAttempts) // NTCP
			{
				peer.numAttempts++;
				auto address = peer.router->GetNTCPAddress (!context.SupportsV6 ()); 
				if (address && !peer.router->UsesIntroducer () && !peer.router->IsUnreachable ())
				{	
					auto s = std::make_shared<NTCPSession> (*m_NTCPServer, peer.router);
					m_NTCPServer->Connect (address->host, address->port, s);
					return true;
				}	
			}
			else  if (peer.numAttempts == 1)// SSU
			{
				peer.numAttempts++;
				if (m_SSUServer)
				{	
					if (m_SSUServer->GetSession (peer.router))
						return true;
				}
			}	
			LogPrint (eLogError, "No NTCP and SSU addresses available");
			m_Peers.erase (ident);
			return false;
		}	
		else // otherwise request RI
		{
			LogPrint ("Router not found. Requested");
			i2p::data::netdb.RequestDestination (ident);
			auto resendTimer = new boost::asio::deadline_timer (m_Service);
			resendTimer->expires_from_now (boost::posix_time::seconds(5)); // 5 seconds
			resendTimer->async_wait (boost::bind (&Transports::HandleResendTimer,
				this, boost::asio::placeholders::error, resendTimer, ident));	
		}	
		return true;
	}	
		
	void Transports::HandleResendTimer (const boost::system::error_code& ecode, 
		boost::asio::deadline_timer * timer, const i2p::data::IdentHash& ident)
	{
		auto it = m_Peers.find (ident);
		if (it != m_Peers.end ())
		{	
			auto r = netdb.FindRouter (ident);
			if (r)
			{
				LogPrint ("Router found. Trying to connect");
				it->second.router = r;
				ConnectToPeer (ident, it->second);
			}	
			else
			{
				LogPrint ("Router not found. Failed to send messages");
				m_Peers.erase (it);
			}	
		}	
		delete timer;
	}	
		
	void Transports::CloseSession (std::shared_ptr<const i2p::data::RouterInfo> router)
	{
		if (!router) return;
		m_Service.post (boost::bind (&Transports::PostCloseSession, this, router));    
	}	

	void Transports::PostCloseSession (std::shared_ptr<const i2p::data::RouterInfo> router)
	{
		auto ssuSession = m_SSUServer ? m_SSUServer->FindSession (router) : nullptr;
		if (ssuSession) // try SSU first
		{	
			m_SSUServer->DeleteSession (ssuSession);
			LogPrint ("SSU session closed");	
		}	
		// TODO: delete NTCP
	}	
		
	void Transports::DetectExternalIP ()
	{
		for (int i = 0; i < 5; i++)
		{
			auto router = i2p::data::netdb.GetRandomRouter ();
			if (router && router->IsSSU () && m_SSUServer)
				m_SSUServer->GetSession (router, true);  // peer test	
		}	
	}
			
	DHKeysPair * Transports::GetNextDHKeysPair ()
	{
		return m_DHKeysPairSupplier.Acquire ();
	}

	void Transports::ReuseDHKeysPair (DHKeysPair * pair)
	{
		m_DHKeysPairSupplier.Return (pair);
	}

	void Transports::PeerConnected (std::shared_ptr<TransportSession> session)
	{
		m_Service.post([session, this]()
		{   
			auto ident = session->GetRemoteIdentity ().GetIdentHash ();
			auto it = m_Peers.find (ident);
			if (it != m_Peers.end ())
			{
				it->second.session = session;
				for (auto it1: it->second.delayedMessages)
					session->SendI2NPMessage (it1);
				it->second.delayedMessages.clear ();
			}
			else // incoming connection
				m_Peers[ident] = { 0, nullptr, session };
		});			
	}
		
	void Transports::PeerDisconnected (std::shared_ptr<TransportSession> session)
	{
		m_Service.post([session, this]()
		{  
			auto ident = session->GetRemoteIdentity ().GetIdentHash ();
			auto it = m_Peers.find (ident);
			if (it != m_Peers.end ())
			{
				if (it->second.delayedMessages.size () > 0)
					ConnectToPeer (ident, it->second);
				else
					m_Peers.erase (it);
			}
		});	
	}	
}
}

