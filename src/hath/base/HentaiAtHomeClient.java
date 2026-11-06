/*

Copyright 2008-2026 E-Hentai.org
https://forums.e-hentai.org/
tenboro@e-hentai.org

This file is part of Hentai@Home.

Hentai@Home is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Hentai@Home is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Hentai@Home.  If not, see <https://www.gnu.org/licenses/>.

*/

/*

1.6.6 [SECURITY, IMPORTANT]

- Corrected a missing directory-traversal check in the H@H Gallery Downloader code that could potentially have allowed the server to tell the client to overwrite any file that was write-accessible for the user H@H was running as with an arbitrary file, by injecting a file path as a filename in the gallery meta file. This breaks the fundamental H@H security principle where the server is never supposed to be able to tell the client to do anything dangerous.

Under some hypothetical and unlikely circumstances, this could have been leveraged by a MitM to do the same thing. Specifically, a malicious party would have had to be in a position to intercept and alter data received from the server, and the client's owner must have actively requested a gallery download via the site at the same time.

There was no way for a MitM to activate the download mechanism independently, as there is no way to start the downloader unless the server explicitly sends a "start the downloader" command to the client - this command cannot be forged unless the client's secret key has been leaked. There are no indicators that this has ever been exploited.

While the activation of the H@H Downloader mechanism has been disabled server-side for any client running versions prior to this update, [b]the potential for the server to activate and exploit this mechanism remains until the client is updated[/b]. As such, we recommend updating as soon as possible, even if you do not use the H@H Downloader.

Due to the security implications, this update will be made mandatory unless any issues are discovered shortly after release.

Thanks to oOoEstheiM for privately reporting this issue.


- Added a signature to RPC responses to detect and reject alterations in general. (This prevents a MitM from interfering with other client operations, but is considered hardening, as it was found to have no significant security impact since H@H was designed not to trust the server in the first place.)

- Added a signature to the gallery downloader meta files to detect and reject altered file lists.

- Added additional hardening to ensure that filenames and filetypes provided to the downloader can only correspond to those that are allowed in the gallery system.

- Since the file hash is not always known when requesting resampled images via the H@H Downloader, and these requests are not latency-sensitive, these file downloads now always use HTTPS. Note that this is not necessary elsewhere, since the hash is otherwise always known, and the file can therefore be verified regardless of transport.

- If we bail out on startup because the available disk space is less than the assigned cache size, we now explicitly print both the required and actual available space.

- The client will now properly handle the FAIL_STARTUP_LOOP and FAIL_UNSUPPORTED_LOCATION startup codes, instead of failing back to re-request the ID and key.


[b]To update an existing client: shut it down, download [url=https://upld.e-hentai.org/hath/HentaiAtHome_1.6.6.zip]Hentai@Home 1.6.6[/url], extract the archive, copy the jar files over the existing ones, then restart the client.[/b]

[b]The full source code for H@H is available and licensed under the GNU General Public License v3, and can be downloaded [url=https://upld.e-hentai.org/hath/HentaiAtHome_1.6.6_src.zip]here[/url]. Building it from source only requires OpenJDK 8 or newer.[/b]

[b]For information on how to join Hentai@Home, check out [url=https://forums.e-hentai.org/index.php?showtopic=19795]The Hentai@Home Project FAQ[/url].[/b]

*/

package hath.base;

import java.io.File;
import java.lang.Thread;
import java.lang.Runtime;

public class HentaiAtHomeClient implements Runnable {
	private InputQueryHandler iqh;
	private Out out;
	private boolean shutdown, reportShutdown, fastShutdown, threadInterruptable, doCertRefresh;
	private HTTPServer httpServer;
	private ClientAPI clientAPI;
	private CacheHandler cacheHandler;
	private ServerHandler serverHandler;
	private Thread myThread;
	private GalleryDownloader galleryDownloader = null;
	private Runtime runtime;
	private int threadSkipCounter;
	private long suspendedUntil;
	private String[] args;

	public HentaiAtHomeClient(InputQueryHandler iqh, String[] args) {
		this.iqh = iqh;
		this.args = args;
		shutdown = false;
		reportShutdown = false;
		threadInterruptable = false;
		runtime = Runtime.getRuntime();

		myThread = new Thread(this);
		myThread.start();
	}

	// master thread for all regularly scheduled tasks
	// note that this function also does most of the program initialization, so that the GUI thread doesn't get locked up doing this when the program is launched through the GUI extension.
	public void run() {
		out = new Out();

		System.setProperty("http.keepAlive", "false");

		Settings.setActiveClient(this);
		Settings.parseArgs(args);

		try {
			Settings.initializeDirectories();
		}
		catch(java.io.IOException ioe) {
			Out.error("Could not create program directories. Check file access permissions and free disk space.");
			System.exit(-1);
		}

		Out.startLoggers();
		Out.info("Hentai@Home " + Settings.CLIENT_VERSION + " (Build " + Settings.CLIENT_BUILD + ") starting up\n");
		Out.info("Copyright (c) 2008-2026, E-Hentai.org - all rights reserved.");
		Out.info("This software comes with ABSOLUTELY NO WARRANTY. This is free software, and you are welcome to modify and redistribute it under the GPL v3 license.\n");

		Stats.resetStats();
		Stats.setProgramStatus("Logging in to main server...");

		// processes commands from the server and interfacing code (like a GUI layer)
		clientAPI = new ClientAPI(this);

		Settings.loadClientLoginFromFile();

		if(!Settings.loginCredentialsAreSyntaxValid()) {
			Settings.promptForIDAndKey(iqh);
		}

		// handles notifications other communication with the hentai@home server
		serverHandler = new ServerHandler(this);
		serverHandler.loadClientSettingsFromServer();

		Stats.setProgramStatus("Initializing cache handler...");

		try {
			// manages the files in the cache
			cacheHandler = new CacheHandler(this);
		}
		catch(java.io.IOException ioe) {
			setFastShutdown();
			dieWithError(ioe);
			return;
		}

		if(isShuttingDown()) {
			return;
		}

		// if something causes the client to terminate after this point, we want the cache to be shut down cleanly to store the state
		java.lang.Runtime.getRuntime().addShutdownHook(new ShutdownHook());

		Stats.setProgramStatus("Starting HTTP server...");

		// handles HTTP connections used to request images and receive commands from the server
		httpServer = new HTTPServer(this);

		if(!httpServer.startConnectionListener(Settings.getClientPort())) {
			setFastShutdown();
			dieWithError("Failed to initialize HTTPServer");
			return;
		}

		Stats.setProgramStatus("Sending startup notification...");

		Out.info("Notifying the server that we have finished starting up the client...");

		if(!serverHandler.notifyStart()) {
			setFastShutdown();
			Out.info("Startup notification failed.");
			return;
		}

		httpServer.allowNormalConnections();
		reportShutdown = true;

		if(Settings.isWarnNewClient()) {
			String newClientWarning = "A new client version is available. Please download it from http://hentaiathome.net/ at your convenience.";
			Out.warning(newClientWarning);

			if(Settings.getActiveGUI() != null) {
				Settings.getActiveGUI().notifyWarning("New Version Available", newClientWarning);
			}
		}

		if(cacheHandler.getCacheCount() < 1) {
			Out.info("IMPORTANT: Your cache does not yet contain any files. You will not see any traffic for some time.");
			Out.info("For a brand new client, it can take several days to a few weeks before your client has any notable traffic.");
		}

		// check if we're in an active schedule
		serverHandler.refreshServerSettings();

		Stats.resetBytesSentHistory();
		Stats.programStarted();

		cacheHandler.processBlacklist(259200);

		suspendedUntil = 0;
		threadSkipCounter = 1;

		long lastThreadTime = 0;

		System.gc();

		Out.info("Startup completed successfully. Starting normal operation");

		while(!shutdown) {
			// this toggle prevents the thread from calling interrupt on itself in case an error triggers a shutdown from the main thread, which could interfere with interruptable filechannel operations when saving cachehandler state
			// not thread-safe; this variable should not be relied upon outside the shutdown hook
			threadInterruptable = true;

			try {
				long sleeptime = Math.max(1000, Math.min(10000, 10000 - lastThreadTime));
				Out.debug("Main thread sleeping with lastThreadTime=" + lastThreadTime + " sleeptime=" + sleeptime + ", memory total=" + runtime.totalMemory() / 1024 + "KiB free=" + runtime.freeMemory() / 1024 + "KiB max=" + runtime.maxMemory() / 1024 + "KiB");
				myThread.sleep(sleeptime);
			}
			catch(java.lang.InterruptedException e) {
				Out.debug("Main thread sleep was interrupted");
			}

			// thread has left the sleep state and is no longer interruptable
			threadInterruptable = false;

			long startTime = System.currentTimeMillis();

			if(!shutdown && suspendedUntil < System.currentTimeMillis()) {
				Out.debug("Main thread starting cycle at startTime=" + startTime);
				Stats.setProgramStatus("Running");

				if(suspendedUntil > 0) {
					resumeMasterThread();
				}

				if(doCertRefresh) {
					Out.info("Doing internal restart of HTTP server to refresh certs");
					
					if(!serverHandler.notifySuspend()) {
						Out.warning("Failed to contact server to suspend client traffic; will retry");
					}
					else {
						try {
							myThread.sleep(5000);
							httpServerShutdown(true);

							int restartTimeout = 0;
							
							do {
								Out.info("Waiting for HTTPServer thread to fully terminate..." + (restartTimeout > 1 ? " (waited " + (restartTimeout * 5) + " seconds)" : ""));
								myThread.sleep(5000);
							} while(!httpServer.isThreadTerminated() && ++restartTimeout < 60);
							
							myThread.sleep(1000);
						} catch(java.lang.InterruptedException e) {}

						httpServer = new HTTPServer(this);

						if(!httpServer.startConnectionListener(Settings.getClientPort())) {
							setFastShutdown();
							dieWithError("Failed to reinitialize HTTPServer");
							return;
						}
						
						httpServer.allowNormalConnections();
						serverHandler.stillAliveTest(true);
						
						doCertRefresh = false;

						Out.info("Internal HTTP server was successfully restarted");
					}
				}
				else if(threadSkipCounter % 11 == 0) {
					//Out.debug("Running serverHandler.stillAliveTest");
					serverHandler.stillAliveTest(false);
				}

				if(threadSkipCounter % 30 == 1) {
					if(Math.abs(Settings.getServerTimeDelta()) > 86400) {
						Out.warning("Your system time seems to be off by more than 24 hours. You should shut down the client and correct your system time to ensure correct operation.");
					}

					if(httpServer.isCertExpired()) {
						dieWithError("Either the system clock is significantly wrong, or something has gone wrong with certificate renewal. Check your system clock and internet connection, then restart the client manually.");
					}
				}

				if(threadSkipCounter % 6 == 2) {
					//Out.debug("Running httpServer.pruneFloodControlTable");
					httpServer.pruneFloodControlTable();
				}
				
				if(threadSkipCounter % 1440 == 1439) {
					//Out.debug("Running Settings.clearRPCServerFailure");
					Settings.clearRPCServerFailure();
				}

				if(threadSkipCounter % 2160 == 2159) {
					//Out.debug("Running cacheHandler.processBlacklist");
					cacheHandler.processBlacklist(43200);
				}

				//Out.debug("Running cacheHandler.cycleLRUCacheTable");
				cacheHandler.cycleLRUCacheTable();

				//Out.debug("Running httpServer.nukeOldConnections");
				httpServer.nukeOldConnections();

				//Out.debug("Running Stats.shiftBytesSentHistory");
				Stats.shiftBytesSentHistory();

				System.gc();

				++threadSkipCounter;
			}
			else {
				Out.debug("Main thread is inactive (suspendedUntil=" + suspendedUntil + " shutdown=" + shutdown + ")");
			}

			lastThreadTime = System.currentTimeMillis() - startTime;
		}
	}
	
	public void setCertRefresh() {
		doCertRefresh = true;
	}

	public boolean isSuspended() {
		return suspendedUntil > System.currentTimeMillis();
	}

	public boolean suspendMasterThread(int suspendTime) {
		if(suspendTime > 0 && suspendTime <= 86400 && suspendedUntil < System.currentTimeMillis()) {
			Stats.programSuspended();
			long suspendTimeMillis = suspendTime * 1000;
			suspendedUntil = System.currentTimeMillis() + suspendTimeMillis;
			Out.debug("Master thread suppressed for " + (suspendTimeMillis / 1000) + " seconds.");
			return serverHandler.notifySuspend();
		}
		else {
			return false;
		}
	}

	public boolean resumeMasterThread() {
		suspendedUntil = 0;
		threadSkipCounter = 0;
		Stats.programResumed();
		return serverHandler.notifyResume();
	}
	
	public synchronized void startDownloader() {
		if(galleryDownloader == null) {
			galleryDownloader = new GalleryDownloader(this);
		}
	}
	
	public void deleteDownloader() {
		galleryDownloader = null;
	}

	public InputQueryHandler getInputQueryHandler() {
		return iqh;
	}

	public HTTPServer getHTTPServer() {
		return httpServer;
	}

	public CacheHandler getCacheHandler() {
		return cacheHandler;
	}

	public ServerHandler getServerHandler() {
		return serverHandler;
	}

	public ClientAPI getClientAPI() {
		return clientAPI;
	}

	
	// static crap

	public static void dieWithError(Exception e) {
		e.printStackTrace();
		dieWithError(e.toString());
	}

	public static void dieWithError(String error) {
		Out.error("Critical Error: " + error);
		Stats.setProgramStatus("Died");
		Settings.getActiveClient().shutdown(false, error);
	}

	public void setFastShutdown() {
		Out.flushLogs();
		fastShutdown = true;
	}

	public void shutdown() {
		shutdown(false, null);
	}

	private void shutdown(String error) {
		shutdown(false, error);
	}

	private void shutdown(boolean fromShutdownHook, String shutdownErrorMessage) {
		Out.flushLogs();

		if(!shutdown) {
			shutdown = true;
			Out.info("Shutting down...");

			if(reportShutdown) {
				if(serverHandler != null) {
					serverHandler.notifyShutdown();
				}

				if(!fastShutdown && httpServer != null) {
					Out.info("Shutdown in progress - please wait up to 30 seconds");
					httpServerShutdown(false);
				}
			}

			if(threadInterruptable) {
				myThread.interrupt();
			}

			if(Math.random() > 0.99) {
				Out.info(
"                             .,---.\n" +
"                           ,/XM#MMMX;,\n" +
"                         -%##########M%,\n" +
"                        -@######%  $###@=\n" +
"         .,--,         -H#######$   $###M:\n" +
"      ,;$M###MMX;     .;##########$;HM###X=\n" +
"    ,/@##########H=      ;################+\n" +
"   -+#############M/,      %##############+\n" +
"   %M###############=      /##############:\n" +
"   H################      .M#############;.\n" +
"   @###############M      ,@###########M:.\n" +
"   X################,      -$=X#######@:\n" +
"   /@##################%-     +######$-\n" +
"   .;##################X     .X#####+,\n" +
"    .;H################/     -X####+.\n" +
"      ,;X##############,       .MM/\n" +
"         ,:+$H@M#######M#$-    .$$=\n" +
"              .,-=;+$@###X:    ;/=.\n" +
"                     .,/X$;   .::,\n" +
"                         .,    ..    \n");
			}
			else {
				String[] sd = {"I don't hate you", "Whyyyyyyyy...", "No hard feelings", "Your business is appreciated", "Good-night"};
				Out.info(sd[(int) Math.floor(Math.random() * sd.length)]);
			}

			if(cacheHandler != null) {
				cacheHandler.terminateCache();
			}

			if(shutdownErrorMessage != null) {
				if(Settings.getActiveGUI() != null) {
					Settings.getActiveGUI().notifyError(shutdownErrorMessage);
				}
			}

			Out.disableLogging();
		}

		if(!fromShutdownHook) {
			System.exit(0);
		}
	}
	
	private void httpServerShutdown(boolean restart) {
		try {
			Thread.currentThread().sleep(5000);
		} catch(java.lang.InterruptedException e) {}

		httpServer.stopConnectionListener(restart);
		int closeWaitCycles = 0, maxWaitCycles = 25;
		
		while(++closeWaitCycles < maxWaitCycles && Stats.getOpenConnections() > 0) {
			try {
				Thread.currentThread().sleep(1000);
			} catch(java.lang.InterruptedException e) {}
			
			if(closeWaitCycles % 5 == 0) {
				Out.info("Waiting for " + Stats.getOpenConnections() + " request(s) to finish; will wait for another " + (maxWaitCycles - closeWaitCycles) + " seconds");
			}
		}
	}

	public boolean isShuttingDown() {
		return shutdown;
	}

	public static void main(String[] args) {
		InputQueryHandler iqh = null;

		try {
			iqh = InputQueryHandlerCLI.getIQHCLI();
			new HentaiAtHomeClient(iqh, args);
		}
		catch(Exception e) {
			Out.error("Failed to initialize InputQueryHandler");
		}
	}

	private class ShutdownHook extends Thread {
		public void run() {
			shutdown(true, null);
		}
	}
}