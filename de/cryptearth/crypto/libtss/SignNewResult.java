package de.cryptearth.crypto.libtss;
import java.util.*;
public record SignNewResult(long session, List<Message> messages)
{
}
