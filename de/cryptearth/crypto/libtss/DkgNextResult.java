package de.cryptearth.crypto.libtss;
import java.util.*;
public record DkgNextResult(long keyShare, byte[] pubkeyPackage, List<Message> messages, boolean complete)
{
}
