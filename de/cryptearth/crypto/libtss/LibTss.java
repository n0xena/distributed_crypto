package de.cryptearth.crypto.libtss;
import java.util.*;
public final class LibTss
{
	private LibTss() {}
	public static void init(int flags) { init0(flags); }
	public static byte[] handleGroupKey(long handle) { return handleGroupKey0(handle); }
	public static byte[] handlePubkeyPackage(long handle) { return handlePubkeyPackage0(handle); }
	public static byte[] handleExport(long handle) { return handleExport0(handle); }
	public static long handleImport(byte[] data, int suite) { return handleImport0(data, suite); }
	public static DkgNewResult dkgNew(int suite, int selfId, int maxSigners, int minSigners, byte[] sessionId)
	{
		DkgNewResult0 result=dkgNew0(suite, selfId, maxSigners, minSigners, sessionId);
		return new DkgNewResult(result.session(), extractMessages(result.messages()));
	}
	public static DkgNextResult dkgNext(long session, List<Message> messages)
	{
		DkgNextResult0 result=dkgNext0(session, buildMessages(messages));
		return new DkgNextResult(result.keyShare(), result.pubkeyPackage(), extractMessages(result.messages()), result.complete());
	}
	public static SignNewResult signNew(long keyShare, byte[] hash, int[] counterparties, byte[] signId)
	{
		SignNewResult0 result=signNew0(keyShare, hash, counterparties, signId);
		return new SignNewResult(result.session(), extractMessages(result.messages()));
	}
	public static SignNextResult signNext(long session, List<Message> messages)
	{
		SignNextResult0 result=signNext0(session, buildMessages(messages));
		return new SignNextResult(result.signature(), extractMessages(result.messages()), result.complete());
	}
	public static void handleFree(long handle) { handleFree0(handle); }
	public static void sessionFree(long session) { sessionFree0(session); }
	private static List<Message> extractMessages(byte[] data)
	{
		List<Message> messages=new ArrayList<>();
		int count=messageCount0(data);
		for(int i=0; i<count; i++)
		{
			messages.add(messageAt0(data, i));
		}
		return messages;
	}
	private static byte[] buildMessages(List<Message> messages)
	{
		byte[] data=null;
		for(Message message : messages)
		{
			data=messageBuild0(data, message.from(), message.to(), message.data());
		}
		return data;
	}
	private static native void init0(int flags);
	private static native byte[] handleGroupKey0(long handle);
	private static native byte[] handlePubkeyPackage0(long handle);
	private static native byte[] handleExport0(long handle);
	private static native long handleImport0(byte[] data, int suite);
	private static native int messageCount0(byte[] messages);
	private static native Message messageAt0(byte[] messages, int index);
	private static native byte[] messageBuild0(byte[] messages, int from, int to, byte[] data);
	private static native DkgNewResult0 dkgNew0(int suite, int selfId, int maxSigners, int minSigners, byte[] sessionId);
	private static native DkgNextResult0 dkgNext0(long session, byte[] messages);
	private static native SignNewResult0 signNew0(long keyShare, byte[] hash, int[] counterparties, byte[] signId);
	private static native SignNextResult0 signNext0(long session, byte[] messages);
	private static native void handleFree0(long handle);
	private static native void sessionFree0(long session);
}
