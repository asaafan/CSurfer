package burp;

public enum AntiCSRFTokenStatus 
{
	TOKEN_UPDATED,
	TOKEN_ADDED, 
	TOKENS_GARBAGE_COLLECTED, 
	TOKENS_LESS_THAN_MAX /* The tokens was not garbage collected because the number of sessions is less than the max */
}
