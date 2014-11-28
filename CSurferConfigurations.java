package burp;

public class CSurferConfigurations 
{		
	public int MAX_NUM_SESSIONS = 100;
	public String ANTI_CSRF_TOKEN_NAME = "TOKEN";
	public String SESSION_ID_NAME = "SESSIONID";
	public String ANTI_CSRF_RESPONSE_REGEX = "\\.TOKEN\".*value=\"(.*?)\">";
	public int ANTI_CSRF_RESPONSE_REGEX_MATCH_GROUP = 1;

		
	public void Update(CSurferConfigurations configurations) 
	{
		this.MAX_NUM_SESSIONS = configurations.MAX_NUM_SESSIONS;
		this.ANTI_CSRF_RESPONSE_REGEX = configurations.ANTI_CSRF_RESPONSE_REGEX;
		this.ANTI_CSRF_RESPONSE_REGEX_MATCH_GROUP = configurations.ANTI_CSRF_RESPONSE_REGEX_MATCH_GROUP;
		this.ANTI_CSRF_TOKEN_NAME = configurations.ANTI_CSRF_TOKEN_NAME;
		this.SESSION_ID_NAME = configurations.SESSION_ID_NAME;
		
		
	} 
}
