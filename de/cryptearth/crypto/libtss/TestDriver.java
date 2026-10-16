package de.cryptearth.crypto.libtss;
import org.bouncycastle.jce.*;
import org.bouncycastle.jce.spec.*;
import org.bouncycastle.math.ec.*;
import org.bouncycastle.openssl.jcajce.*;
import java.util.*;
import java.io.*;
import java.security.*;
import java.security.spec.*;
public class TestDriver
{
	public static class User
	{
		int id;
		DkgNewResult newResult;
		DkgNextResult nextResult;
		List<Message> messages;
		byte[] keyshare;
		byte[] groupkey;
		byte[] pubkeyPackage;
		public User(int id)
		{
			this.id=id;
		}
		public int getId() { return id; }
		public void setNewResult(DkgNewResult newResult) { this.newResult=newResult; }
		public DkgNewResult getNewResult() { return newResult; }

		public void setNextResult(DkgNextResult nextResult) { this.nextResult=nextResult; }
		public DkgNextResult getNextResult() { return nextResult; }

		public void setMessages(List<Message> messages) { this.messages=messages; }
		public List<Message> getMessages() { return messages; }

		public void setKeyshare(byte[] keyshare) { this.keyshare=keyshare; }
		public byte[] getKeyshare() { return keyshare; }

		public void setGroupkey(byte[] groupkey) { this.groupkey=groupkey; }
		public byte[] getGroupkey() { return groupkey; }

		public void setPubkeyPackage(byte[] pubkeyPackage) { this.pubkeyPackage=pubkeyPackage; }
		public byte[] getPubkeyPackage() { return pubkeyPackage; }
	}
	public static void main(String... args) throws Exception
	{
		System.loadLibrary("libtss_jni");
		LibTss.init(0);
		int userCount=5;
		int threshold=3;
		byte[] sessionID="test-dkg".getBytes();
		List<User> users=new ArrayList<>();
		for(int i=1; i<=userCount; i++)
		{
			users.add(new User(i));
		}
		for(User user : users)
		{
			user.setNewResult(LibTss.dkgNew(7, user.getId(), userCount, threshold, sessionID));
			user.setMessages(user.getNewResult().messages());
		}
		Map<Integer, List<Message>> messageMap=new HashMap<>();
		for(User user : users)
		{
			messageMap.put(user.getId(), user.getMessages());
		}
		printMessageMap(messageMap);
		System.out.print("simulate traffic ... ");
		messageMap=simulateTraffic(messageMap);
		System.out.println("done");
		printMessageMap(messageMap);
		for(User user : users)
		{
			user.setMessages(messageMap.get(user.getId()));
		}
		System.out.println("phase 2");
		for(User user : users)
		{
			long session=user.getNewResult().session();
			DkgNextResult nextResult=LibTss.dkgNext(session, user.getMessages());
			user.setNextResult(nextResult);
			user.setMessages(nextResult.messages());
		}
		for(User user : users)
		{
			messageMap.put(user.getId(), user.getMessages());
		}
		printMessageMap(messageMap);
		System.out.print("simulate traffic ... ");
		messageMap=simulateTraffic(messageMap);
		System.out.println("done");
		printMessageMap(messageMap);
		for(User user : users)
		{
			user.setMessages(messageMap.get(user.getId()));
		}
		System.out.println("phase 3");
		for(User user : users)
		{
			long session=user.getNewResult().session();
			DkgNextResult nextResult=LibTss.dkgNext(session, user.getMessages());
			user.setNextResult(nextResult);
			user.setMessages(nextResult.messages());
		}
		for(User user : users)
		{
			messageMap.put(user.getId(), user.getMessages());
		}
		printMessageMap(messageMap);
		System.out.print("simulate traffic ... ");
		messageMap=simulateTraffic(messageMap);
		System.out.println("done");
		printMessageMap(messageMap);
		for(User user : users)
		{
			user.setMessages(messageMap.get(user.getId()));
		}
		System.out.println("phase 4");
		for(User user : users)
		{
			long session=user.getNewResult().session();
			DkgNextResult nextResult=LibTss.dkgNext(session, user.getMessages());
			System.out.println(nextResult.complete());
			user.setNextResult(null);
			user.setMessages(null);
			user.setKeyshare(LibTss.handleExport(nextResult.keyShare()));
			user.setGroupkey(LibTss.handleGroupKey(nextResult.keyShare()));
			user.setPubkeyPackage(LibTss.handlePubkeyPackage(nextResult.keyShare()));
			LibTss.handleFree(nextResult.keyShare());
			LibTss.sessionFree(session);
			int id=user.getId();
			OutputStream out=new FileOutputStream(new File(String.format("keys_java/%d-keyshare", id)));
			out.write(user.getKeyshare());
			out.flush();
			out.close();
			out=new FileOutputStream(new File(String.format("keys_java/%d-groupkey", id)));
			out.write(user.getGroupkey());
			out.flush();
			out.close();
			out=new FileOutputStream(new File(String.format("keys_java/%d-pubkeypackage", id)));
			out.write(user.getPubkeyPackage());
			out.flush();
			out.close();
		}
		byte[] groupkey=users.get(0).getGroupkey();
		ECNamedCurveParameterSpec spec=ECNamedCurveTable.getParameterSpec("secp256r1");
		org.bouncycastle.math.ec.ECPoint bcpoint=spec.getCurve().decodePoint(groupkey);
		java.security.spec.ECPoint jpoint=new java.security.spec.ECPoint(bcpoint.getAffineXCoord().toBigInteger(), bcpoint.getAffineYCoord().toBigInteger());
		KeyFactory keyFactory=KeyFactory.getInstance("EC");
		AlgorithmParameters parameters=AlgorithmParameters.getInstance("EC");
		parameters.init(new ECGenParameterSpec("secp256r1"));
		java.security.spec.ECParameterSpec p256=parameters.getParameterSpec(java.security.spec.ECParameterSpec.class);
		java.security.spec.ECPublicKeySpec keyspec=new java.security.spec.ECPublicKeySpec(jpoint, p256);
		PublicKey publicKey=keyFactory.generatePublic(keyspec);
		Writer writer=new FileWriter(new File("keys_java/pub.pem"));
		JcaPEMWriter jcaPEMWriter=new JcaPEMWriter(writer);
		jcaPEMWriter.writeObject(publicKey);
		jcaPEMWriter.flush();
		writer.flush();
		jcaPEMWriter.close();
		writer.close();
	}
	public static void printMessageMap(Map<Integer, List<Message>> messageMap)
	{
		for(Map.Entry<Integer, List<Message>> entry : messageMap.entrySet())
		{
			int user=entry.getKey();
			List<Message> messages=entry.getValue();
			for(int j=0; j<messages.size(); j++)
			{
				Message message=messages.get(j);
				System.out.println(String.format("user: %d, message: %d, from: %d, to: %d, length: %d", user, j+1, message.from(), message.to(), message.data().length));
			}
		}
	}
	public static Map<Integer, List<Message>> simulateTraffic(Map<Integer, List<Message>> messageMap)
	{
		Map<Integer, List<Message>> resultMap=new HashMap<>();
		for(int user : messageMap.keySet())
		{
			resultMap.put(user, new ArrayList<Message>());
		}
		for(Map.Entry<Integer, List<Message>> entry : messageMap.entrySet())
		{
			int sender=entry.getKey();
			for(Message message : entry.getValue())
			{
				int from=message.from();
				int to=message.to();
				if(to==0)
				{
					for(int recipient : messageMap.keySet())
					{
						if(recipient==from)
						{
							continue;
						}
						resultMap.get(recipient).add(message);
					}
				}
				else
				{
					resultMap.get(to).add(message);
				}
			}
		}
		return resultMap;
	}
}
