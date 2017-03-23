/*  
  Copyright (C) 2017 William Welna (wwelna@occultusterra.com)
  
  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.

  https://github.com/Sanguinarious/atomikron
*/

package com.occultusterra.atomikron;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.Inet4Address;
import java.text.SimpleDateFormat;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.codec.binary.Base64;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.namednumber.TcpPort;
//import org.pcap4j.util.NifSelector;

import com.google.gson.JsonObject;
import com.occultusterra.watchdog.atomikron.JSONEvents;
import com.splunk.Service;
import com.splunk.ServiceArgs;

public class App {
	static ServiceArgs loginArgs = new ServiceArgs();
	static Service service;
	static int ID;
	static String INDEX;
	static String SOURCE;
	
	static {
		loginArgs.setUsername(System.getProperty("U", ""));
		loginArgs.setPassword(System.getProperty("P", ""));
		loginArgs.setHost(System.getProperty("S", ""));
		ID = Integer.parseInt(System.getProperty("I", "0"));
		loginArgs.setPort(8089);
		service = Service.connect(loginArgs);
		
		INDEX = "main";
		SOURCE = "atomikron";
	}
	
	public static String getJSONDate() {
		ZonedDateTime zdate = ZonedDateTime.now(ZoneId.of("UTC"));
		return zdate.format(DateTimeFormatter.ISO_DATE_TIME);
	}
	
	public static void put_string(String filename, String data) throws IOException {
		File h = new File(filename);
		try(FileOutputStream f = new FileOutputStream(h, true)) {
			f.write(data.getBytes());
		}
	}
	
	public static String filedate() {
		Date now = new Date();
		SimpleDateFormat now_format = new SimpleDateFormat("yyMMdd");
		return now_format.format(now);
	}
	
	public static void main(String[] args) throws Exception {
		new App(args);
	}
	
	public App(String[] args) throws Exception {
		InputStream in = this.getClass().getResourceAsStream("/LICENSE.txt"); 
		BufferedReader reader = new BufferedReader(new InputStreamReader(in));
		String line;
		while((line=reader.readLine())!=null)
			System.out.println(line);
		try {
			PcapNetworkInterface nif;
		    try {
		    	//nif = new NifSelector().selectNetworkInterface(); 
		    	List<PcapNetworkInterface> Devs = Pcaps.findAllDevs();
		    	nif = Pcaps.getDevByName(Devs.get(ID).getName());
		    }
		    catch (Exception e) { e.printStackTrace(); return;}
		    if (nif == null) {return;}

		    final PcapHandle pcap = nif.openLive(65536, PromiscuousMode.PROMISCUOUS, 10);
		    pcap.setFilter("tcp port 80", BpfCompileMode.OPTIMIZE);
		    
		    List<String> cache = new ArrayList<>();
			pcap.loop(-1, new PacketListener(){
				Pattern REQUEST_REGEX = Pattern.compile("^(?<method>[A-Z]+)[\\s](?<url>[A-Za-z-._~:\\/?#\\[\\]@!$&'()*+,;=`.]+)[\\s](?<version>[A-Z\\/\\.0-9]+)$");
				Pattern HEADERS_REGEX = Pattern.compile("^(?<field>.+):\\s(?<value>.+)$");
				
				public void gotPacket(Packet packet) {
					try {
					if(packet.contains(IpV4Packet.class) && packet.contains(TcpPacket.class)) {
					Inet4Address ip = packet.get(IpV4Packet.class).getHeader().getDstAddr();
					TcpPort port = packet.get(TcpPacket.class).getHeader().getDstPort();
					if(port.valueAsInt() == 80) {
						if((packet.get(TcpPacket.class).getPayload()!=null)) {
							String line;
							BufferedReader reader = new BufferedReader(new InputStreamReader(new ByteArrayInputStream(packet.get(TcpPacket.class).getPayload().getRawData())));
							while((line=reader.readLine())!=null) {
								Matcher h = REQUEST_REGEX.matcher(line);
								if(h.find()) {
									JsonObject event = new JsonObject();
									event.addProperty("DATE_INTERCEPTED", getJSONDate());
									event.addProperty("IP", ip.toString().replaceAll("[^0-9\\.]", ""));
									event.addProperty("PORT", port.valueAsInt());
									event.addProperty("REQUEST_METHOD", h.group("method"));
									event.addProperty("REQUEST_URL", h.group("url"));
									event.addProperty("REQUEST_VERSION", h.group("version"));
									while((line=reader.readLine())!=null) {
										Matcher m = HEADERS_REGEX.matcher(line);
										if(m.find())
											event.addProperty("HTTP_"+m.group("field"), m.group("value"));
										else {
											if(line.length()==0) // Empty new line & end of HTTP REQUEST
												break;
										}
									}
									if(h.group("method").equals("POST") && line != null) {
										StringBuilder sb = new StringBuilder();
										while((line=reader.readLine())!=null)
											sb.append(line); // Get POST body
										String x = sb.toString();
										if(x.matches("[ -~\\r\\n]+")) {
											event.addProperty("POST_BODY", x);
										} else {
											if(x.length()<7000)
												event.addProperty("POST_BODY_BINARY_DATA", new String(Base64.encodeBase64(x.getBytes())));
											else
												event.addProperty("POST_BODY_BINARY_DATA", "<!BINARY CONTENT OVER 7k!>");
											 //System.out.println("<<<<"+x+">>>>");
										}
									} // equals("POST");
									cache.add(event.toString());
									put_string(INDEX+filedate()+".json", event.toString()+"\n");
									try {
										if(cache.size()>100) {
											JSONEvents events = new JSONEvents(service, INDEX, SOURCE);
											events.addline(cache);
											events.submit();
											cache.clear();
										}
									} catch(Exception e) { e.printStackTrace(); }
									//System.out.println(event);
									break;
								} // h.find();
							} // readLine();
						} // getPayload != null
					} // is port 80
				}} catch(Exception e) {e.printStackTrace();} // gotPacket End
			}}); // End Loop
			pcap.close();
			try {
				if(cache.size()>100) {
					JSONEvents events = new JSONEvents(service, INDEX, SOURCE);
					events.addline(cache);
					events.submit();
					cache.clear();
				}
			} catch(Exception e) { e.printStackTrace(); }
		} catch(Exception e) {e.printStackTrace();}
    }
}
