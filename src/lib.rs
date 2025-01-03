#[macro_use]
extern crate lazy_static;
use byteorder::{BigEndian, ByteOrder};
use rand::Rng;

use std::io;
use std::io::Result;
use std::net::SocketAddr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use tokio::net::{TcpListener, TcpStream};
use dnsclient::r#async::DNSClient;
use tokio::io::*;

pub async fn dns_lookup(host: String) -> Result<String>{
	lazy_static!{
		static ref DNS_OBJECT: DNSClient = {
			let mut upstream = Vec::new();
			upstream.push(dnsclient::UpstreamServer::new(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53)));
			upstream.push(dnsclient::UpstreamServer::new(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)), 53)));
			upstream.push(dnsclient::UpstreamServer::new(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53)));
			upstream.push(dnsclient::UpstreamServer::new(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)), 53)));

			let mut dns = DNSClient::new(upstream);
			dns.set_timeout(std::time::Duration::from_millis(1000));

			dns
		};

		static ref GOOGLE_IP: [String; 3] = [
			"34.64.4.113".to_string(),
			"142.250.198.14".to_string(),
			"142.250.199.110".to_string()
		];
	}
	
	/*
		if 'google.com' in q_name or 'google.co.' in q_name or 'youtube.com' in q_name or 'googleapis.com' in q_name or 'gstatic.com' in q_name or 'googleusercontent.com' in q_name or 'google-analytics.com' in q_name or 'widevine.com' in q_name or 'blogger.com' in q_name or 'blogspot.' in q_name or 'ytimg.com' in q_name or 'ggpht.com' in q_name or 'recaptcha.net' in q_name:
				
		cnt_google = cnt_google + 1
		
		AResult = [q_name + " 136 A 216.58.197.238", q_name + " 136 A 216.58.197.206", q_name + " 136 A 216.58.197.174"]
		random.shuffle(AResult)
		
	*/
	


	if 
		host.contains("google.com") || host.contains("google.co.") || 
		host.contains("youtube.com") || host.contains("ytimg.com") || host.contains("ggpht.com") || 
		host.contains("googleapis.com") || host.contains("gstatic.com") || host.contains("googleusercontent.com") || 
		host.contains("google-analytics.com") || host.contains("google.com") || 
		host.contains("recaptcha.com") || 
		host.contains("widevine.com") || 
		host.contains("blogspot.com") || host.contains("blogspot.co.kr") || host.contains("blogger.com")
	{
		let mut rand_instance = rand::thread_rng();
		let selected_ip = (*GOOGLE_IP)[rand_instance.gen_range(0..2)].clone();

		return Ok(selected_ip);
	}
	

	let dns = (*DNS_OBJECT).clone();
	let mut result = dns.query_a(host.as_str()).await?;
	
	if result.len() == 1{
		return Ok(result.pop().unwrap().to_string());
	}

	let mut rand_instance = rand::thread_rng();
	let pos = rand_instance.gen_range(0..result.len() - 1);


	Ok(result.remove(pos).to_string())
}



pub trait Encoder: Send + Sync {
	fn encode(&mut self, buf: &[u8]) -> &[u8];
	fn decode(&mut self, buf: &mut [u8], len: usize) -> Result<usize>;
	fn clone_box(&self) -> Box<dyn Encoder>;
}

impl Clone for Box<dyn Encoder> {
	fn clone(&self) -> Box<dyn Encoder> {
		self.clone_box()
	}
}

async fn copy<'a, T: AsyncRead + Unpin, U: AsyncWrite + Unpin>(
	stream1: &'a mut T,
	stream2: &'a mut U,
) -> io::Result<()> {
	let mut buf = [0; 4096];
	let len = stream1.read(&mut buf).await?;
	if len == 0 {
		return Err(io::Error::from(io::ErrorKind::BrokenPipe));
	}
	
	stream2.write_all( &buf[..len]).await?;
	Ok(())
}

async fn handle(mut stream: TcpStream) -> Result<()> {
	let mut buf = [0; 2048];

	let len = stream.read(&mut buf).await?;
	
	if 1 + 1 + (buf[1] as usize) != len || buf[0] != b'\x05' {
		println!("invalid header");
		return Ok(());
	}
	stream.write_all(b"\x05\x00").await?;

	let len = stream.read(&mut buf).await?;
	if len <= 4 {
		println!("invalid proto");
		return Ok(());
	}

	let ver = buf[0];
	let cmd = buf[1];
	let atyp = buf[3];

	if ver != b'\x05' {
		println!("invalid proto");
		return Ok(());
	}

	if cmd != 1 {
		println!("Command not supported");
		stream.write_all(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00").await?;
		return Ok(());
	}

	let addr;
	match atyp {
		1 => {
			if len != 10 {
				println!("invalid proto");
				return Ok(());
			}
			let dst_addr = IpAddr::V4(Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]));
			let dst_port = BigEndian::read_u16(&buf[8..]);
			addr = SocketAddr::new(dst_addr, dst_port).to_string();
		}
		3 => {
			let offset = 4 + 1 + (buf[4] as usize);
			if offset + 2 != len {
				println!("invalid proto");
				return Ok(());
			}
			let dst_port = BigEndian::read_u16(&buf[offset..]);

			let mut dst_addr = dns_lookup(std::str::from_utf8(&buf[5..offset]).unwrap().to_string()).await?;
			dst_addr.push(':');
			dst_addr.push_str(&dst_port.to_string());
			addr = dst_addr;
		}
		4 => {
			if len != 22 {
				println!("invalid proto");
				return Ok(());
			}
			let dst_addr = IpAddr::V6(Ipv6Addr::new(
				((buf[4] as u16) << 8) | buf[5] as u16,
				((buf[6] as u16) << 8) | buf[7] as u16,
				((buf[8] as u16) << 8) | buf[9] as u16,
				((buf[10] as u16) << 8) | buf[11] as u16,
				((buf[12] as u16) << 8) | buf[13] as u16,
				((buf[14] as u16) << 8) | buf[15] as u16,
				((buf[16] as u16) << 8) | buf[17] as u16,
				((buf[18] as u16) << 8) | buf[19] as u16,
			));
			let dst_port = BigEndian::read_u16(&buf[20..]);
			addr = SocketAddr::new(dst_addr, dst_port).to_string();
		}
		_ => {
			println!("Address type not supported, type={}", atyp);
			stream.write_all(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00").await?;
			return Ok(());
		}
	}

	println!("incoming socket, request upstream: {:?}", addr);
	let mut up_stream = match TcpStream::connect(addr).await {
		Ok(s) => s,
		Err(e) => {
			println!("Upstream connect failed, {}", e);
			stream.write_all(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00").await?;
			return Ok(());
		}
	};

	stream.write_all(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00").await?;

	let (mut ri, mut wi) = stream.split();
	let (mut ro, mut wo) = up_stream.split();

	loop {
		tokio::select! {
			_ = ro.readable() => {
				if (copy(&mut ro, &mut wi)
					.await).is_err() {
						break
					}
			},
			_ = ri.readable() => {
				if (copy(&mut ri, &mut wo)
				.await).is_err() {
					break;
				}
			}
		}
	}

	
	Ok(())
}

pub async fn run_socks5(addr: SocketAddr) -> Result<()> {
	let listener = TcpListener::bind(&addr).await?;
	println!("Listening on: {}", addr);

	loop {
		let (stream, _) = listener.accept().await?;

		tokio::spawn(async move {
			handle(stream).await.unwrap();
		});
	}
}
