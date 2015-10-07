package burp;

public class AntiCSRFToken 
{
	public String tokenValue;
	public String sessionID;
	private boolean isTokenBeingUsed;
	private static final int MAX_LOCK_RETRIES = 2000;
	private static final long SLEEP_TIME_MS = 40;
	
	public AntiCSRFToken(String tokenValue, String sessionID)
	{
		this.tokenValue = tokenValue;
		this.sessionID = sessionID;
	}
	
	public void ReleaseToken() 
	{
		System.out.println("Lock released for " + this.sessionID);
		this.isTokenBeingUsed = false;		
		
	}



	public void LockToken() throws InterruptedException 
	{
		int retries = 0;
		while(retries < AntiCSRFToken.MAX_LOCK_RETRIES)
		{
			if(!isTokenBeingUsed)
			{
				// Lock token
				this.isTokenBeingUsed = true;	
				return;
			}
			else
			{			
				Thread.sleep(AntiCSRFToken.SLEEP_TIME_MS);
				retries++;
			
			}
		}
		
		System.out.println("Mutex Lock timeout... Releasing Lock for " + this.sessionID);
		this.ReleaseToken();
		return;

		
	}

}
