package org.example.check;

import static org.example.util.PrivacyAPISummary.API_TYPE_INIT;
import static org.example.util.PrivacyAPISummary.sdks;

import java.io.StringWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Vector;
import java.util.stream.Collectors;

import org.example.util.PrivacyAPISummary;
import org.example.util.Utils;
import org.example.util.PrivacyAPISummary.APIDescriptor;
import org.example.util.Utils.ValueError;
import org.example.xq.Globals;
import org.json.JSONArray;
import org.json.JSONObject;

import soot.Body;
import soot.Scene;
import soot.SootMethod;
import soot.Unit;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.jimple.toolkits.callgraph.ReachableMethods;
import soot.toolkits.scalar.Pair;

// this detector is used to generate some landscape data, e.g., which SDKs are integrated in which apps?
public class PrivacyLandscape {
	public static Map<String, Set<String>> sdkConnectionsCombined = new HashMap<>();
	public static Map<String, Set<String>> sdkConnectionsStrict = new HashMap<>();
	public static Map<String, Set<String>> sdkConnectionsRough = new HashMap<>();
	public static Map<String, String> sdkDomainMap = new HashMap<>(); // <sdk name, sdk domain>

	public static void analyze() {
		Map<Pair<String, String>, String> initApiToSdkName = new HashMap<Pair<String, String>, String>();
		for (String sdkName : PrivacyAPISummary.sdks.keySet()) {
			for (APIDescriptor descriptor : PrivacyAPISummary.sdks.get(sdkName)) {
				if (descriptor.apiType != PrivacyAPISummary.API_TYPE_INIT) {
					continue;
				}
				initApiToSdkName.put(new Pair<String, String>(descriptor.apiClazzName, descriptor.apiMethodName),
						sdkName);
			}
		}

		ReachableMethods rm = Scene.v().getReachableMethods();
		for (Iterator rmIterator = Scene.v().getReachableMethods().listener(); rmIterator.hasNext();) {
			SootMethod m = (SootMethod) rmIterator.next();
			Pair<String, String> apiSig = new Pair<String, String>(m.getDeclaringClass().getName(), m.getName());
			if (initApiToSdkName.containsKey(apiSig)) {
				JSONObject obj = new JSONObject();
				obj.put("FlawType", "SDKInApp");
				obj.put("SdkName", initApiToSdkName.get(apiSig));
				obj.put("SdkInitMethod", apiSig);
				obj.put("ApkPath", Globals.APK_PATH);
				obj.put("PackageName", Globals.PACKAGE_NAME);

				StringWriter out = new StringWriter();
				obj.write(out);
				Utils.LOGGER.info(out.toString());
			}
		}

		buildSdkConnectionsStrict();
		buildSdkConnectionsRough();
		
		apiOrderAnalysis();
	}
	
	/*
	 * This method is used to log the order when privacy apis (including init) are invoked in a method,
	 * which is potentially useful for detecting the timing constraints specified in the SDK documents. 
	 */
	private static void apiOrderAnalysis() {
		// <api class name, api method name> --> set<<sdk, api type>>
		Map<Pair<String, String>, Set<Pair<String, String>>> apiToTypes = new HashMap<>();
		
		for (String sdkName : PrivacyAPISummary.sdks.keySet()) {
			for (APIDescriptor descriptor : PrivacyAPISummary.sdks.get(sdkName)) {
				if (descriptor.apiClazzName == null || descriptor.apiMethodName == null) {
					continue;
				}
				
				apiToTypes.computeIfAbsent(new Pair<>(descriptor.apiClazzName, descriptor.apiMethodName), 
						k -> new HashSet<>()).add(new Pair<>(sdkName, descriptor.apiType));
			}
		}
		
		CallGraph cg = Scene.v().getCallGraph();
		
		ReachableMethods rm = Scene.v().getReachableMethods();
		for (Iterator rmIterator = Scene.v().getReachableMethods().listener(); rmIterator.hasNext();) {
			SootMethod m = (SootMethod) rmIterator.next();
			
			List<Pair<Pair<String, String>, Integer>> privacyAPILocations = new ArrayList<>();
			
			if (!m.hasActiveBody()) {
				continue;
			}
			
			Body body = m.getActiveBody();
			
			// We assume this is in order
			int unitIndex = 0;
			for (Unit unit : body.getUnits()) {
				for (Iterator<Edge> it = cg.edgesOutOf(unit); it.hasNext();) {
                    Edge edge = it.next();
                    SootMethod target = edge.tgt();
                    Pair<String, String> targetKey = new Pair<>(target.getDeclaringClass().getName(), target.getName());
                    if (apiToTypes.containsKey(targetKey)) {
                    	privacyAPILocations.add(new Pair<>(targetKey, unitIndex));
                    }
				}
				unitIndex += 1;
			}
			
			if (privacyAPILocations.size() < 1) {
				continue;
			}
			
			int coppaAPIIndex = -1;
			int initAPIIndex = -1;
			
			for (int idx = privacyAPILocations.size() - 1; idx >= 0; --idx) {
				Pair<Pair<String, String>, Integer> privacyAPI = privacyAPILocations.get(idx);
				Set<Pair<String, String>> sdkAndTypes = apiToTypes.get(privacyAPI.getO1());
				
				for (Pair<String, String> snt : sdkAndTypes) {
					if (snt.getO2() == PrivacyAPISummary.API_TYPE_INIT) {
						initAPIIndex = privacyAPI.getO2();
					}
					
					if (snt.getO2() == PrivacyAPISummary.API_TYPE_COPPA) {
						coppaAPIIndex = privacyAPI.getO2();
					}
				}
			}
			
			JSONObject obj = new JSONObject();
			obj.put("FlawType", "PrivacyAPILocation");
			obj.put("CallerMethodSignature", m.getSignature());
			obj.put("CoppaAfterInit", coppaAPIIndex > initAPIIndex && coppaAPIIndex != -1 && initAPIIndex != -1);
			
			JSONArray privacyAPIArray = new JSONArray();
			for (Pair<Pair<String, String>, Integer> privacyAPI : privacyAPILocations) {
				JSONObject apiObj = new JSONObject();
				apiObj.put("APIClassName", privacyAPI.getO1().getO1());
				apiObj.put("APIMethodName", privacyAPI.getO1().getO2());
				apiObj.put("APILocation", privacyAPI.getO2());
				apiObj.put("APITypes", apiToTypes.get(privacyAPI.getO1()));
				privacyAPIArray.put(apiObj);
			}
			obj.put("PrivacyAPIs", privacyAPIArray);
			
			obj.put("ApkPath", Globals.APK_PATH);
			obj.put("PackageName", Globals.PACKAGE_NAME);

			StringWriter out = new StringWriter();
			obj.write(out);
			Utils.LOGGER.info(out.toString());
		}
	}

	// build an sdk connection as long as the "init" function is called in a domain
	private static void buildSdkConnectionsRough() {
		sdkDomainMap = getSDKsDomain(sdks);

		// for each sdk
		for (String sdk : sdks.keySet()) {
			List<PrivacyAPISummary.APIDescriptor> apiDescriptors = sdks.get(sdk);
			// for each privacy api
			for (PrivacyAPISummary.APIDescriptor descriptor : apiDescriptors) {
				if (descriptor.apiType != PrivacyAPISummary.API_TYPE_INIT || descriptor.apiClazzName == null
						|| descriptor.apiMethodName == null) {
					continue;
				}

				HashMap<String, Set<String>> xrefs = Utils.getXrefWithOverrides(descriptor.apiClazzName,
						descriptor.apiMethodName);
				// for each privacy api's overload
				for (HashMap.Entry<String, Set<String>> each_ref : xrefs.entrySet()) {
					Set<String> callers = each_ref.getValue();

					// for each caller
					for (String caller : callers) {
						String callerTopDomain = Utils.getTopDomain(Utils.getClassFromMethodSignature(caller));
						if (callerTopDomain.equals(sdkDomainMap.get(sdk))) {
							continue;
						}
						
						Set<String> keysWithCallerTopDomain = new HashSet<>();
						for (String key : sdkDomainMap.keySet()) {
							if (sdkDomainMap.get(key).equals(callerTopDomain)) {
								keysWithCallerTopDomain.add(key);
							}
						}

						// if the caller is an SDK in the current app
						if (keysWithCallerTopDomain.size() == 1) {
							String wrapperSdk = keysWithCallerTopDomain.iterator().next();
							Set<String> innerMapCombined = sdkConnectionsCombined.computeIfAbsent(wrapperSdk, k -> new HashSet<>());
							innerMapCombined.add(sdk);
							
							if (!sdkConnectionsStrict.containsKey(wrapperSdk) || !sdkConnectionsStrict.get(wrapperSdk).contains(sdk)) {
								// Save the wrapper sdk's information to wrapper_sdk_map as <wrapper_sdk,
								// <callee1_sdk, <API_type1, API_type2, ...>>>
								Set<String> innerMap = sdkConnectionsRough.computeIfAbsent(wrapperSdk, k -> new HashSet<>());
								innerMap.add(sdk);
								
								JSONObject obj = new JSONObject();
								obj.put("FlawType", "SDKConnectionRough");
								obj.put("CallerSdkName", wrapperSdk);
								obj.put("CalleeSdkName", sdk);
								obj.put("ApkPath", Globals.APK_PATH);
								obj.put("PackageName", Globals.PACKAGE_NAME);

								StringWriter out = new StringWriter();
								obj.write(out);
								Utils.LOGGER.info(out.toString());
							}
						} else if (keysWithCallerTopDomain.isEmpty()) {
							continue;
						} else {
							Utils.LOGGER.info("ERROR:>>>>>>>>>>>>>>>>>>>>");
							Utils.LOGGER.info("sdk_domain_map:>>>>>>>");
							sdkDomainMap.forEach((name, domain) -> {
								Utils.LOGGER.info("SDK Name: " + name + ", SDK Domain: " + domain);
							});
							// throw new ValueError("More than one sdk is mapped to the domain:>>" +
							// caller_top_domain);
						}
					}
				}
			}
		}
	}

	private static Map<String, String> getSDKsDomain(Map<String, List<APIDescriptor>> sdks) {
		Map<String, String> domain_list = new HashMap<>();
		for (String key : sdks.keySet()) {
			List<PrivacyAPISummary.APIDescriptor> apiDescriptors = sdks.get(key);
			String domain = "";
			for (PrivacyAPISummary.APIDescriptor descriptor : apiDescriptors) {
				if (descriptor.apiClazzName == null) {
					continue;
				}
				if (descriptor.apiType == API_TYPE_INIT) {
					domain = Utils.getTopDomain(descriptor.apiClazzName);
				}
				if (!domain.equals("")) {
					domain_list.put(key, domain);
					break;
				}
			}
		}
		return domain_list;
	}

	// build an sdk connection when the "init" function of a wrapper calls the
	// "init" of an individual sdk
	private static void buildSdkConnectionsStrict() {
		Map<Pair<String, String>, String> initApiToSdkName = new HashMap<Pair<String, String>, String>();

		for (String sdkName : PrivacyAPISummary.sdks.keySet()) {
			for (APIDescriptor descriptor : PrivacyAPISummary.sdks.get(sdkName)) {
				if (descriptor.apiType != PrivacyAPISummary.API_TYPE_INIT || descriptor.apiClazzName == null) {
					continue;
				}
				initApiToSdkName.put(new Pair<String, String>(descriptor.apiClazzName, descriptor.apiMethodName),
						sdkName);
			}
		}
		
		Utils.LOGGER.info(String.format("initApiToSdkName Keyset %s", initApiToSdkName));

		/*
		for (Pair<String, String> callerInitApi : initApiToSdkName.keySet()) {
			String callerSdkName = initApiToSdkName.get(callerInitApi);
			
			if (!callerSdkName.equals("adMost")) {
				continue;
			}
			
			Set<Pair<String, String>> reachable = Utils.findPathsBFSNoPaths(callerInitApi.getO1(),
					callerInitApi.getO2(), initApiToSdkName.keySet());
			
			for (Pair<String, String> calleeApi : reachable) {				
				Utils.LOGGER.info(String.format("Finding path: <%s, %s> -- <%s, %s>", callerInitApi.getO1(), callerInitApi.getO2(), calleeApi.getO1(), calleeApi.getO2()));
				
				String calleeSdkName = initApiToSdkName.get(calleeApi);
				if (callerSdkName != calleeSdkName) {// && pathDomains.size() <= 3) {
					Set<String> innerMapCombined = sdkConnectionsCombined.computeIfAbsent(callerSdkName, k -> new HashSet<>());
					innerMapCombined.add(calleeSdkName);
					
					Set<String> innerMap = sdkConnectionsStrict.computeIfAbsent(callerSdkName, k -> new HashSet<>());
					innerMap.add(calleeSdkName);
					
					JSONObject obj = new JSONObject();
					obj.put("FlawType", "SDKConnectionStrict");
					obj.put("CallerSdkName", callerSdkName);
					obj.put("CalleeSdkName", calleeSdkName);
					obj.put("ApkPath", Globals.APK_PATH);
					obj.put("PackageName", Globals.PACKAGE_NAME);

					StringWriter out = new StringWriter();
					obj.write(out);
					Utils.LOGGER.info(out.toString());
				}
			}
		}*/
		
		
		for (Pair<String, String> callerInitApi : initApiToSdkName.keySet()) {
			String callerSdkName = initApiToSdkName.get(callerInitApi);
			
			Map<SootMethod, List<List<SootMethod>>> paths = Utils.findPathsBFS(callerInitApi.getO1(),
					callerInitApi.getO2(), initApiToSdkName.keySet());

			for (SootMethod calleeApi : paths.keySet()) {
				Utils.LOGGER.info(String.format("Finding paths <%s, %s> --- %s (%d)", callerInitApi.getO1(), callerInitApi.getO2(), calleeApi.getSignature(), paths.size()));
				
				for (List<SootMethod> path : paths.get(calleeApi)) {
					Set<String> pathDomains = new HashSet<String>();
					for (SootMethod pathMethod : path) {
						pathDomains.add(Utils.getTopDomain(pathMethod.getDeclaringClass().getName()));
					}
					
					Pair<String, String> calleeKey = new Pair<>(calleeApi.getDeclaringClass().getName(), calleeApi.getName());
					if (!initApiToSdkName.containsKey(calleeKey)) {
						continue;
					}
					
					// we considering two connecting SDKs, without covering transitive sdks that
					// covers +3 sdks.
					String calleeSdkName = initApiToSdkName.get(calleeKey);
					if (callerSdkName != calleeSdkName && pathDomains.size() <= 3) {
						Set<String> innerMapCombined = sdkConnectionsCombined.computeIfAbsent(callerSdkName, k -> new HashSet<>());
						innerMapCombined.add(calleeSdkName);
						
						Set<String> innerMap = sdkConnectionsStrict.computeIfAbsent(callerSdkName, k -> new HashSet<>());
						innerMap.add(calleeSdkName);
						
						JSONObject obj = new JSONObject();
						obj.put("FlawType", "SDKConnectionStrict");
						obj.put("CallerSdkName", callerSdkName);
						obj.put("CalleeSdkName", calleeSdkName);
						obj.put("PathDomains", pathDomains.size());
						JSONArray pathArray = new JSONArray();
						for (SootMethod pathElement : path) {
							pathArray.put(pathElement.getSignature());
						}
						obj.put("CallPath", pathArray);
						obj.put("ApkPath", Globals.APK_PATH);
						obj.put("PackageName", Globals.PACKAGE_NAME);

						StringWriter out = new StringWriter();
						obj.write(out);
						Utils.LOGGER.info(out.toString());
					}
				}
			}
		}
	}
}
