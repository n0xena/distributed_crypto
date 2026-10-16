package de.cryptearth.crypto.libtss;
import java.util.*;
public record SignNextResult(byte[] signature, List<Message> messages, boolean complete)
{
}
