package de.cryptearth.crypto.libtss;
public final class TssException extends RuntimeException
{
	private final int status;
	public TssException(int status, String message)
	{
		super(message);
		this.status=status;
	}
	public int status() { return status; }
}
