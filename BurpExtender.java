package burp;

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.beans.PropertyChangeListener;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.Action;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

//import burp.*;

public class BurpExtender implements IHttpListener, ITab {
	
	 
	public IBurpExtenderCallbacks mycallbacks;
	public IExtensionHelpers myhelpers;
	private CSurferTokenJar latestAntiCSRFTokens;
	private CSurferJpanel panel;
	public static CSurferConfigurations CSurferConfigurator;
	
		
	/*This method is invoked at startup. It is needed if you are implementing any method of IBurpExtenderCallbacks interface.
	In this example, we have implemented three such methods of this interface.*/
	public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
	{
		mycallbacks = callbacks;
		myhelpers = mycallbacks.getHelpers();
   	  	callbacks.setExtensionName("Burp Proxy Modifier");
   	  	BurpExtender.CSurferConfigurator = new CSurferConfigurations();
   	  	
   	  	callbacks.registerHttpListener(this);
   	  	this.latestAntiCSRFTokens = new CSurferTokenJar();
	    
   	 
   	  	// create the UI in a separate thread
		SwingUtilities.invokeLater(new Runnable() 
		{					  
			@Override
		      public void run()
		      {
					panel = new CSurferJpanel();
					panel.Init();
					BurpExtender.CSurferConfigurator = panel.GetConfigurations();
					
					//Add save handler to update configurations
					panel.saveButton.addActionListener(new ActionListener() {											

						@Override
						public void actionPerformed(ActionEvent arg0) {
//							BurpExtender.CSurferConfigurator.Update(panel.getConfigurations());
							BurpExtender.CSurferConfigurator = panel.GetConfigurations();
							
						}
					});
					
					callbacks.customizeUiComponent(panel);		          		          		        
					callbacks.addSuiteTab(BurpExtender.this);
										
		      }
		  });
		
	}



	@Override
	public void processHttpMessage(int toolFlag, boolean isRequest, IHttpRequestResponse messageInfo)			
	{		
		IRequestInfo request = myhelpers.analyzeRequest(messageInfo.getRequest());
		String currentSessionID = this.ExtractSessionID(request);		
		
//		System.out.println("Parameter value: " + BurpExtender.CSurferConfigurator.parameter1);
		
		if(isRequest)
		{				
			this.UpdateAntiCSRFToken(request, messageInfo, currentSessionID);							
		}
		else //Response
		{
			IResponseInfo response = myhelpers.analyzeResponse(messageInfo.getResponse());
			this.UpdateAntiCSRFToken(response, messageInfo, currentSessionID);									
		}
	
	}



	private String ExtractSessionID(IRequestInfo request) 
	{
		List<IParameter> parameters = request.getParameters();		
		for (IParameter parameter : parameters) 
		{
			if(parameter.getName().equals(BurpExtender.CSurferConfigurator.SESSION_ID_NAME) && parameter.getType() == IParameter.PARAM_COOKIE)
			{
				return parameter.getValue();
			}
		}		
		return null;
	}



	private void UpdateAntiCSRFToken(IResponseInfo response, IHttpRequestResponse messageInfo, String sessionID)  
	{		
		int bodyOffset = response.getBodyOffset();
		byte[] bodyBytes = Arrays.copyOfRange(messageInfo.getResponse(), bodyOffset, messageInfo.getResponse().length);
		String body = myhelpers.bytesToString(bodyBytes);
		Pattern tokenPattern = Pattern.compile(BurpExtender.CSurferConfigurator.ANTI_CSRF_RESPONSE_REGEX);
		Matcher matcher = tokenPattern.matcher(body);		
		if (matcher.find()) 
		{
			String newTokenValue = matcher.group(BurpExtender.CSurferConfigurator.ANTI_CSRF_RESPONSE_REGEX_MATCH_GROUP);
			
			
			
			//Handle the case if there's a new cookie sent in the response, so the session ID is going to be the new one, not the old
			String newSessionID = this.GetNewSessionID(response);
			
			if(newSessionID != null)
				sessionID = newSessionID;
			
			AntiCSRFTokenStatus status = this.latestAntiCSRFTokens.AddToken(newTokenValue, sessionID);
			
			switch(status)
			{		
			case TOKEN_ADDED:
				System.out.println("Token found in response: " + newTokenValue + ". Added for session ID " + sessionID);
				
				break;
			case TOKEN_UPDATED:
				System.out.println("Token found in response: " + newTokenValue + ". Updated for session ID " + sessionID);			
				break;
			default:
				throw new UnknownError();			
			}
			
			status = this.latestAntiCSRFTokens.GarbageCollect();
			
			switch (status) {
			case TOKENS_GARBAGE_COLLECTED:
				System.out.println("Tokens garbage collector: succefully cleaned.");
				break;

			case TOKENS_LESS_THAN_MAX:
				System.out.println("Tokens garbage collector: tokens less than max.");
				break;
				
			default:
				throw new UnknownError();	
			}
			
			
		}
		
	}



	private String GetNewSessionID(IResponseInfo response) 
	{
		List<ICookie> cookies = response.getCookies();		
		for (ICookie cookie : cookies) 
		{
			if(cookie.getName().equals(BurpExtender.CSurferConfigurator.SESSION_ID_NAME))
			{
				return cookie.getValue();
			}
		}
		return null;
	}



	private void UpdateAntiCSRFToken(IRequestInfo request, IHttpRequestResponse messageInfo, String sessionID) 
	{				
		List<IParameter> parameters = request.getParameters();
		
		for (IParameter parameter : parameters) 
		{
			if(parameter.getName().equals(BurpExtender.CSurferConfigurator.ANTI_CSRF_TOKEN_NAME))
			{
				String currentTokenValue = this.latestAntiCSRFTokens.GetToken(sessionID);
												
				//If Anti-CSRF token is incorrect and we have a newer value, then correct it
				if(currentTokenValue != null && !parameter.getValue().equals(currentTokenValue))
				{
					IParameter newParameter = myhelpers.buildParameter(
							parameter.getName(), currentTokenValue, parameter.getType());
					
					messageInfo.setRequest(myhelpers.updateParameter(
						messageInfo.getRequest(), newParameter));
					System.out.println("Token updated in reqeust: " + currentTokenValue + " for session ID: " + sessionID);
				}

				//Stop inspecting further parameters
				break;			
			}			
		}
	}



	@Override
	public String getTabCaption() 
	{
		return "CSurfer";
	}



	@Override
	public Component getUiComponent() 
	{
		return this.panel;
	}


}
