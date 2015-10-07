package burp;

import java.util.ArrayList;

public class CSurferTokenJar 
{	
	
	
	public ArrayList<AntiCSRFToken> tokens;
	
	public CSurferTokenJar()
	{
		this.tokens = new ArrayList<>();
	}
		
	
	public AntiCSRFTokenStatus AddToken(String tokenValue, String sessionID)
	{
		for (AntiCSRFToken antiCSRFToken : tokens) 
		{
			//if session ID matches, update token value
			if (sessionID.equals(antiCSRFToken.sessionID))
			{
				//A new value is received for the token, 
				antiCSRFToken.tokenValue = tokenValue;
				//so now we remove the lock and it can be used again
				antiCSRFToken.ReleaseToken();
				
				return AntiCSRFTokenStatus.TOKEN_UPDATED;
			}									
		}
		
		//otherwise, session not present, then add it
		AntiCSRFToken newToken = new AntiCSRFToken(tokenValue, sessionID);
		this.tokens.add(newToken);
		return AntiCSRFTokenStatus.TOKEN_ADDED;
		
	}
	
	public String GetToken(String sessionID)
	{
		for (AntiCSRFToken antiCSRFToken : tokens) 
		{			
			if(antiCSRFToken.sessionID!= null && antiCSRFToken.sessionID.equals(sessionID))
			{
				// Someone requested the token, so we'll lock it until it is updated again or timed out
				try 
				{
					antiCSRFToken.LockToken();					
				} 
				catch (InterruptedException e) 
				{
					antiCSRFToken.ReleaseToken();
					e.printStackTrace();
				}
				
				return antiCSRFToken.tokenValue;
			}
		}
		
		return null;
	}
	
	
	public AntiCSRFTokenStatus GarbageCollect()
	{
		if(this.tokens.size()> BurpExtender.CSurferConfigurator.MAX_NUM_SESSIONS)
		{
			for (int i=0;i<BurpExtender.CSurferConfigurator.MAX_NUM_SESSIONS /2 ;i++)
			{
				this.tokens.remove(0);
			}
			return AntiCSRFTokenStatus.TOKENS_GARBAGE_COLLECTED;
		}
		else
			return AntiCSRFTokenStatus.TOKENS_LESS_THAN_MAX;
	}
}
