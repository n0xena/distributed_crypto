package de.cryptearth.crypto.libtss;
import java.io.*;
import java.util.*;
import java.security.*;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.openssl.*;
import org.bouncycastle.openssl.jcajce.*;
public class TestDriver2
{
	public static class User
	{
		int id;
		long keyshare;
		long session;
		int[] counterParties;
		List<Message> messages;
		public User(int id, int[] counterParties)
		{
			this.id=id;
			this.counterParties=counterParties;
		}

		public void setSession(long session) { this.session=session; }
		public long getSession() { return session; }

		public int getId() { return id; }

		public void setKeyshare(long keyshare) { this.keyshare=keyshare; }
		public long getKeyshare() { return keyshare; }

		public int[] getCounterParties() { return counterParties; }

		public void setMessages(List<Message> messages) { this.messages=messages; }
		public List<Message> getMessages() { return messages; }
	}
	public static void main(String... args) throws Exception
	{
		System.loadLibrary("libtss_jni");
		LibTss.init(0);
		PEMParser pemParser=new PEMParser(new FileReader(new File("keys_java/pub.pem")));
		Object object=pemParser.readObject();
		pemParser.close();
		PublicKey publicKey=(new JcaPEMKeyConverter()).getPublicKey((SubjectPublicKeyInfo)object);
		byte[] testData=new byte[128];
		(new Random()).nextBytes(testData);
		MessageDigest messageDigest=MessageDigest.getInstance("SHA256");
		messageDigest.update(testData);
		byte[] hash=messageDigest.digest();
		byte[] signId="test-sign".getBytes();
		List<User> users=new ArrayList<>();
		users.add(new User(1, new int[] {3, 5}));
		users.add(new User(3, new int[] {1, 5}));
		users.add(new User(5, new int[] {1, 3}));
		for(User user : users)
		{
			InputStream in=new FileInputStream(new File(String.format("keys_java/%d-keyshare", user.getId())));
			user.setKeyshare(LibTss.handleImport(in.readAllBytes(), 7));
			in.close();
			SignNewResult newResult=LibTss.signNew(user.getKeyshare(), hash, user.getCounterParties(), signId);
			user.setSession(newResult.session());
			user.setMessages(newResult.messages());
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
			long session=user.getSession();
			SignNextResult nextResult=LibTss.signNext(session, user.getMessages());
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
			long session=user.getSession();
			SignNextResult nextResult=LibTss.signNext(session, user.getMessages());
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
		byte[] sig=new byte[0];
		for(User user : users)
		{
			long session=user.getSession();
			SignNextResult nextResult=LibTss.signNext(session, user.getMessages());
			System.out.println(nextResult.complete());
			sig=nextResult.signature();
			System.out.println(sig.length);
			LibTss.handleFree(user.getKeyshare());
			LibTss.sessionFree(user.getSession());
		}
		sig=rawEcdsaToDer(sig);
		Signature signature=Signature.getInstance("SHA256withECDSA");
		signature.initVerify(publicKey);
		signature.update(testData);
		System.out.println(signature.verify(sig));
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

public static byte[] rawEcdsaToDer(byte[] raw) {
    if (raw.length != 64) {
        throw new IllegalArgumentException("Expected 64-byte raw ECDSA signature");
    }

    byte[] r = derInteger(raw, 0, 32);
    byte[] s = derInteger(raw, 32, 32);

    int bodyLength = 2 + r.length + 2 + s.length;

    byte[] der = new byte[2 + bodyLength];
    int pos = 0;

    der[pos++] = 0x30;
    der[pos++] = (byte) bodyLength;

    der[pos++] = 0x02;
    der[pos++] = (byte) r.length;
    System.arraycopy(r, 0, der, pos, r.length);
    pos += r.length;

    der[pos++] = 0x02;
    der[pos++] = (byte) s.length;
    System.arraycopy(s, 0, der, pos, s.length);

    return der;
}

private static byte[] derInteger(byte[] raw, int offset, int length) {
    int start = offset;

    // Strip leading zeroes, but leave at least one byte.
    while (start < offset + length - 1 && raw[start] == 0) {
        start++;
    }

    int len = offset + length - start;

    // DER INTEGER is signed. If MSB is 1, prepend 00.
    boolean prependZero = (raw[start] & 0x80) != 0;

    byte[] result = new byte[len + (prependZero ? 1 : 0)];

    if (prependZero) {
        System.arraycopy(raw, start, result, 1, len);
    } else {
        System.arraycopy(raw, start, result, 0, len);
    }

    return result;
}

}
