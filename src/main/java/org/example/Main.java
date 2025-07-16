package org.example;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.example.check.APIDisconnection;
import org.example.check.HardCodeConfiguration;
import org.example.check.MisssingConfiguration;
import org.example.check.PrivacyAPITracking;
import org.example.check.PrivacyLandscape;
import org.example.check.UnevenPrivacySupport;
import org.example.xq.AnalysisAPIs;
import org.example.xq.Globals;

import soot.Scene;
import soot.SootMethod;
import soot.jimple.toolkits.callgraph.ReachableMethods;
import soot.toolkits.scalar.Pair;

import org.example.util.PrivacyAPILoader;
import org.example.util.PrivacyAPISummary;
import org.example.util.Utils;
import org.example.util.PrivacyAPISummary.APIDescriptor;

public class Main {
	public static void main(String[] args) throws Exception {
		if (args.length != 1) {
			System.err.println("Provide Params <APK_PATH>");
			System.exit(-1);
		}

		String apkPath = args[0];
		new Main().run(apkPath);
	}

	private void run(String apkPath) {
		String platformPath = "./platforms";
		Globals.setupApkForAnalysis(apkPath, platformPath);
		
		long startTime = 0;
		long endTime = 0;
		startTime = System.currentTimeMillis();
		Main.this.runAnalysisReachability();
		endTime = System.currentTimeMillis();
		Utils.LOGGER.info(String.format("#FINISH# Analysis of %s costs %d seconds", Globals.APK_PATH, (endTime - startTime) / 1000));
	}
	
	private void runAnalysisReachability() {
		long startTime = 0;
		long endTime = 0;
		
		startTime = System.currentTimeMillis();
		
		// Set up paths & privacy API string
		PrivacyAPILoader.loadPrivacyAPIs("res/Priv_impl.json");
		// Set up custom code in Flowdroid
		AnalysisAPIs.buildCallGraphWithFlowDroid();
		
		Map<Pair<String, String>, String> apiToSDK = new HashMap<>();
		for (String sdk : PrivacyAPISummary.sdks.keySet()) {
			List<APIDescriptor> apis = PrivacyAPISummary.sdks.get(sdk);
			for (APIDescriptor api : apis) {
				if (api.apiType != PrivacyAPISummary.API_TYPE_INIT || api.apiClazzName == null) {
					continue;
				}
				apiToSDK.put(new Pair<>(api.apiClazzName, api.apiMethodName), sdk);
			}
		}
		
		ReachableMethods rm = Scene.v().getReachableMethods();
		for (Iterator rmIterator = Scene.v().getReachableMethods().listener(); rmIterator.hasNext();) {
			SootMethod m = (SootMethod) rmIterator.next();
			Pair<String, String> mSig = new Pair<>(m.getDeclaringClass().getName(), m.getName());
			
			if (apiToSDK.containsKey(mSig)) {
				System.out.println("SDK API Found: " + m.getSignature() + "---" + apiToSDK.get(mSig));
			}
		}
		
		endTime = System.currentTimeMillis();
		Utils.LOGGER.info(String.format("#STEP# buildCallGraphWithFlowDroid for %s costs %d seconds", Globals.APK_PATH, (endTime - startTime) / 1000));
	}

	private void runAnalysis() {
		long startTime = 0;
		long endTime = 0;
		
		startTime = System.currentTimeMillis();
		
		// Set up paths & privacy API string
		PrivacyAPILoader.loadPrivacyAPIs("res/Priv_impl.json");
		// Set up custom code in Flowdroid
		AnalysisAPIs.setupDefaultEntries();
		AnalysisAPIs.buildCallGraphWithSystemPatcher();
		AnalysisAPIs.postProcessCallGraph();
		
		endTime = System.currentTimeMillis();
		Utils.LOGGER.info(String.format("#STEP# Preprocess of %s costs %d seconds", Globals.APK_PATH, (endTime - startTime) / 1000));


		/*
		 * CallGraph cg = Scene.v().getCallGraph(); for (Iterator<Edge> it =
		 * cg.iterator(); it.hasNext();) { Edge edge = it.next();
		 * Utils.LOGGER.info(String.format("Edge, %s --- %s", edge.getSrc(),
		 * edge.getTgt())); }
		 */

		startTime = System.currentTimeMillis();
		try {
			PrivacyLandscape.analyze();
		} catch (Exception e) {
			e.printStackTrace();
		}
		endTime = System.currentTimeMillis();
		Utils.LOGGER.info(String.format("#STEP# PrivacyLandscape of %s costs %d seconds", Globals.APK_PATH, (endTime - startTime) / 1000));
		
		startTime = System.currentTimeMillis();
		// this needs to be called after PrivacyAPITracking so that it can leverage
		// data flow analysis results.
		APIDisconnection apiDisconnection = new APIDisconnection();
		try {
			apiDisconnection.analyzeCallGraph(Scene.v().getCallGraph());
		} catch (Exception e) {
			e.printStackTrace();
		}
		endTime = System.currentTimeMillis();
		Utils.LOGGER.info(String.format("#STEP# APIDisconnection.analyzeCallGraph of %s costs %d seconds", Globals.APK_PATH, (endTime - startTime) / 1000));
		
		startTime = System.currentTimeMillis();
		try {
			new MisssingConfiguration().runAnalysis();
		} catch (Exception e) {
			e.printStackTrace();
		}
		endTime = System.currentTimeMillis();
		Utils.LOGGER.info(String.format("#STEP# MisssingConfiguration of %s costs %d seconds", Globals.APK_PATH, (endTime - startTime) / 1000));

		
		startTime = System.currentTimeMillis();
		try {
			new UnevenPrivacySupport().analyze(Scene.v().getCallGraph());
		} catch (Exception e) {
			e.printStackTrace();
		}
		endTime = System.currentTimeMillis();
		Utils.LOGGER.info(String.format("#STEP# UnevenPrivacySupport of %s costs %d seconds", Globals.APK_PATH, (endTime - startTime) / 1000));

		
		startTime = System.currentTimeMillis();
		try {
			new PrivacyAPITracking().runAnalysis();
		} catch (Exception e) {
			e.printStackTrace();
		}
		endTime = System.currentTimeMillis();
		Utils.LOGGER.info(String.format("#STEP# PrivacyAPITracking of %s costs %d seconds", Globals.APK_PATH, (endTime - startTime) / 1000));
		
		
		startTime = System.currentTimeMillis();
		// this needs to be called after PrivacyAPITracking so that it can leverage
		// InterproceduralConstantValuePropagator of FlowDroid
		try {
			HardCodeConfiguration.run_analyze(Scene.v().getCallGraph());
		} catch (Exception e) {
			e.printStackTrace();
		}
		endTime = System.currentTimeMillis();
		Utils.LOGGER.info(String.format("#STEP# HardCodeConfiguration of %s costs %d seconds", Globals.APK_PATH, (endTime - startTime) / 1000));
		
		
		startTime = System.currentTimeMillis();
		// this needs to be called after PrivacyAPITracking so that it can leverage
		// data flow analysis results.
		try {
			apiDisconnection.postAnalysis();
		} catch (Exception e) {
			e.printStackTrace();
		}
		endTime = System.currentTimeMillis();
		Utils.LOGGER.info(String.format("#STEP# APIDisconnection.postAnalysis of %s costs %d seconds", Globals.APK_PATH, (endTime - startTime) / 1000));
	}
}