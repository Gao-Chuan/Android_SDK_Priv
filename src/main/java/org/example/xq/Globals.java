package org.example.xq;

import java.io.File;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import soot.jimple.Stmt;
import soot.jimple.infoflow.android.axml.AXmlAttribute;
import soot.jimple.infoflow.android.axml.AXmlHandler;
import soot.jimple.infoflow.android.axml.AXmlNode;
import soot.jimple.infoflow.android.manifest.ProcessManifest;
import soot.toolkits.scalar.Pair;

// global settings
public class Globals {
	public static int MAX_DEPTH = 10;

	public static Map<String, Integer> RETURN_IN_PARAMS = new HashMap<String, Integer>();
	static {
		/*
		 * RETURN_IN_PARAMS.put("<android.media.AudioRecord: int read(byte[],int,int)>",
		 * 0); RETURN_IN_PARAMS.
		 * put("<android.media.AudioRecord: int read(byte[],int,int,int)>", 0);
		 * RETURN_IN_PARAMS.
		 * put("<android.media.AudioRecord: int read(java.nio.ByteBuffer,int)>", 0);
		 * RETURN_IN_PARAMS.
		 * put("<android.media.AudioRecord: int read(java.nio.ByteBuffer,int,int)>", 0);
		 * RETURN_IN_PARAMS.
		 * put("<android.media.AudioRecord: int read(float[],int,int,int)>", 0);
		 * RETURN_IN_PARAMS.put("<android.media.AudioRecord: int read(short[],int,int)>"
		 * , 0); RETURN_IN_PARAMS.
		 * put("<android.media.AudioRecord: int read(short[],int,int,int)>", 0);
		 * RETURN_IN_PARAMS.
		 * put("<java.nio.channels.DatagramChannel: java.net.SocketAddress receive(java.nio.ByteBuffer)>"
		 * , 0); RETURN_IN_PARAMS.
		 * put("<java.nio.channels.DatagramChannel: int read(java.nio.ByteBuffer)>", 0);
		 * RETURN_IN_PARAMS.
		 * put("<java.nio.channels.DatagramChannel: long read(java.nio.ByteBuffer[])>",
		 * 0); RETURN_IN_PARAMS.
		 * put("<java.nio.channels.DatagramChannel: long read(java.nio.ByteBuffer[],int,int)>"
		 * , 0); RETURN_IN_PARAMS.
		 * put("<java.net.DatagramSocket: void receive(java.net.DatagramPacket)>", 0);
		 */
	}

	public static List<String> EXCLUDED_ANDROID = Arrays.asList("android.*", "androidx.*", "org.apache.*", "okhttp3.*",
			"org.ksoap2x.*", "com.squareup.*", "retrofit.*", "com.ibm.*", "org.eclipse.paho.*", "org.ksoap2.*",
			"retrofit2.*", "com.loopj.*", "io.fabric.*", "org.springframework.*", "com.octo.android.*",
			"com.android.volley.*", "kotlin.*", "java.*");

	public static List<String> EXCLUDED_LIBS = Arrays.asList("android.*", "androidx.*", "org.apache.*", "okhttp3.*",
			"org.ksoap2x.*", "com.squareup.*", "retrofit.*", "com.ibm.*", "org.eclipse.paho.*", "org.ksoap2.*",
			"retrofit2.*", "com.loopj.*", "io.fabric.*", "org.springframework.*", "com.octo.android.*",
			"com.android.volley.*", "kotlin.*", "java.*");

	public static Set<Pair<String, String>> ENTRY_POINTS;
	public static Map<Pair<String, String>, Set<String>> STMT_SOURCE_SIGS;

	public static String APK_PATH;
	public static String LAUNCHER_ACTIVITY_NAME;
	public static String PACKAGE_NAME;
	public static String OUTPUT_DIR;
	public static String CONFIG_DIR;
	public static String FRAMEWORK_DIR;
	public static String JIMPLE_DIR;
	public static String JIMPLE_SUBDIR;
	public static String SRC_SINK_FILE;
	public static String LOG_FILE;
	public static ExtraSourceFilter EXTRA_SOURCE_FILTER;
	public static ExtraEntryPointFilter EXTRA_ENTRY_POINT_FILTER;
	public static Set<String> REACHABLE_METHODS;

	public static void setupApkForAnalysis(String apkPath, String framework_dir) {
		/* set up all paths */
		ENTRY_POINTS = new HashSet<Pair<String, String>>();
		STMT_SOURCE_SIGS = new HashMap<Pair<String, String>, Set<String>>();
		APK_PATH = apkPath;
		FRAMEWORK_DIR = framework_dir;
		File directory = new File(".");
		String pwd = directory.getAbsolutePath();

		String fileSeparator = (apkPath.contains("\\")) ? "\\" : "/";

		OUTPUT_DIR = "." + fileSeparator + "res" + fileSeparator + "output" + fileSeparator;
		CONFIG_DIR = "." + fileSeparator + "res" + fileSeparator + "config" + fileSeparator;
		JIMPLE_DIR = "." + fileSeparator + "res" + fileSeparator + "jimple_output" + fileSeparator;

		String filename = APK_PATH.substring(APK_PATH.lastIndexOf(fileSeparator) + 1, APK_PATH.lastIndexOf(".apk"));
		JIMPLE_SUBDIR = JIMPLE_DIR + fileSeparator + filename + "_jimple";
		SRC_SINK_FILE = OUTPUT_DIR + filename + ".txt";
		LOG_FILE = OUTPUT_DIR + filename + ".log";

		EXTRA_SOURCE_FILTER = new ExtraSourceFilter() {
			@Override
			public boolean shouldIgnoreSource(Stmt stmt, String hostClazzName) {
				return false;
			}
		};

		EXTRA_ENTRY_POINT_FILTER = new ExtraEntryPointFilter() {
			@Override
			public boolean shouldIgnoreEntryPoint(Pair<String, String> entry) {
				return false;
			}
		};

		REACHABLE_METHODS = new HashSet<String>();

		try {
			ProcessManifest processManifest = new ProcessManifest(apkPath);
			Globals.PACKAGE_NAME = processManifest.getPackageName();
			Globals.getLauncherActivityName(processManifest);
			processManifest.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private static void getLauncherActivityName(ProcessManifest processManifest) {
		AXmlHandler axmlh = processManifest.getAXml();
		// Find main activity and remove main intent-filter
		List<AXmlNode> anodes = axmlh.getNodesWithTag("activity");
		for (AXmlNode an : anodes) {
			boolean hasMain = false;
			boolean hasLauncher = false;

			AXmlNode filter = null;
			AXmlAttribute<?> aname = an.getAttribute("name");
			String aval = (String) aname.getValue();

			List<AXmlNode> fnodes = an.getChildrenWithTag("intent-filter");
			for (AXmlNode fn : fnodes) {
				hasMain = false;
				hasLauncher = false;

				// check action
				List<AXmlNode> acnodes = fn.getChildrenWithTag("action");
				for (AXmlNode acn : acnodes) {
					AXmlAttribute<?> acname = acn.getAttribute("name");
					String acval = (String) acname.getValue();
					if (acval.equals("android.intent.action.MAIN")) {
						hasMain = true;
					}
				}
				// check category
				List<AXmlNode> catnodes = fn.getChildrenWithTag("category");
				for (AXmlNode catn : catnodes) {
					AXmlAttribute<?> catname = catn.getAttribute("name");
					String catval = (String) catname.getValue();
					if (catval.equals("android.intent.category.LAUNCHER")) {
						hasLauncher = true;
						filter = fn;
					}
				}

				if (hasLauncher && hasMain) {
					break;
				}
			}
			if (hasLauncher && hasMain) {
				filter.exclude();
				Globals.LAUNCHER_ACTIVITY_NAME = aval;
				break;
			}
		}
	}
}
