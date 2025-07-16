package org.example.check;

import soot.Scene;
import soot.SootMethod;
import soot.Type;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.toolkits.scalar.Pair;

import java.io.StringWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.Vector;
import org.example.xq.Globals;
import org.example.util.PrivacyAPISummary;
import org.example.util.PrivacyAPISummary.APIDescriptor;
import org.example.util.Utils;
import org.javatuples.Sextet;
import org.json.JSONArray;
import org.json.JSONObject;

public class APIDisconnection {
	// sdk1, sdk2, law, apis1, apis2, has any connection
	private List<Sextet<String, String, String, Set<Pair<String, String>>, Set<Pair<String, String>>, Boolean>> expectedAPIConnections = new ArrayList<Sextet<String, String, String, Set<Pair<String, String>>, Set<Pair<String, String>>, Boolean>>();

	public void analyzeCallGraph(CallGraph cg) {
		if (PrivacyLandscape.sdkConnectionsCombined.size() < 1) {
			Utils.LOGGER.info("No SDK Connections Found!");
			return;
		}

		checkPrivacyAPICGConnections(cg);
	}
	
	public void postAnalysis() {
		if (PrivacyLandscape.sdkConnectionsCombined.size() < 1) {
			Utils.LOGGER.info("No SDK Connections Found!");
			return;
		}

		checkPrivacyAPIDFConnections();
	}

	/*
	 * TODO: The matching of APIs needs to consider qualifiers.
	 */
	private void checkPrivacyAPICGConnections(CallGraph cg) {

		// generate api connection expectations
		for (Entry<String, Set<String>> sdkConnectionEntry : PrivacyLandscape.sdkConnectionsCombined.entrySet()) {
			String callerSdk = sdkConnectionEntry.getKey();
			List<APIDescriptor> callerApis = PrivacyAPISummary.sdks.get(callerSdk);
			Map<String, Set<Pair<String, String>>> callerSupportedLaws = new HashMap<String, Set<Pair<String, String>>>();
			for (APIDescriptor callerApi : callerApis) {
				if (callerApi.apiType == PrivacyAPISummary.API_TYPE_INIT || callerApi.apiClazzName == null) {
					continue;
				}
				callerSupportedLaws.computeIfAbsent(callerApi.apiType, k -> new HashSet<>())
						.add(new Pair<>(callerApi.apiClazzName, callerApi.apiMethodName));
			}

			for (String calleeSdk : sdkConnectionEntry.getValue()) {
				List<APIDescriptor> calleeApis = PrivacyAPISummary.sdks.get(calleeSdk);
				Map<String, Set<Pair<String, String>>> calleeSupportedLaws = new HashMap<String, Set<Pair<String, String>>>();
				for (APIDescriptor calleeApi : calleeApis) {
					if (calleeApi.apiType == PrivacyAPISummary.API_TYPE_INIT || calleeApi.apiClazzName == null) {
						continue;
					}
					calleeSupportedLaws.computeIfAbsent(calleeApi.apiType, k -> new HashSet<>())
							.add(new Pair<>(calleeApi.apiClazzName, calleeApi.apiMethodName));
				}

				for (String apiType : callerSupportedLaws.keySet()) {
					if (calleeSupportedLaws.containsKey(apiType)) {
						expectedAPIConnections.add(new Sextet<>(callerSdk, calleeSdk, apiType,
								callerSupportedLaws.get(apiType), calleeSupportedLaws.get(apiType), false));
					}
				}
			}
		}

		// check cg connections; mark connected as long as one pair of APIs are
		// connected (if multiple APIs exist)
		for (int expectedIndex = 0; expectedIndex < expectedAPIConnections.size(); expectedIndex++) {
			Sextet<String, String, String, Set<Pair<String, String>>, Set<Pair<String, String>>, Boolean> sextet = expectedAPIConnections
					.get(expectedIndex);

			Set<Pair<String, String>> expectedCallerApis = sextet.getValue3();
			Set<Pair<String, String>> expectedCalleeApis = sextet.getValue4();

			boolean hasCGConnection = false;
			for (Pair<String, String> callerKey : expectedCallerApis) {
				Map<SootMethod, List<List<SootMethod>>> paths = Utils.findPathsBFS(callerKey.getO1(), callerKey.getO2(),
						expectedCalleeApis);

				for (SootMethod calleeKey : paths.keySet()) {
					for (List<SootMethod> path : paths.get(calleeKey)) {
						ConditionalEnforcementForWrapper.reportSuspiciousConditions(sextet.getValue0(),
								sextet.getValue1(), sextet.getValue2(), path, expectedCalleeApis);
					}
				}

				Utils.LOGGER.info(String.format("API CG Connection: (%d) %s : %s (%s) -- %s (%s)", paths.size(),
						sextet.getValue2(), sextet.getValue0(), callerKey,
						sextet.getValue1(), expectedCalleeApis));

				if (paths.size() > 0) {
					hasCGConnection = true;
					// break;
				}
			}

			if (hasCGConnection) {
				expectedAPIConnections.set(expectedIndex,
						new Sextet<String, String, String, Set<Pair<String, String>>, Set<Pair<String, String>>, Boolean>(
								sextet.getValue0(), sextet.getValue1(), sextet.getValue2(), sextet.getValue3(),
								sextet.getValue4(), true));
			}
		}
	}
	
	private void checkPrivacyAPIDFConnections() {
		Map<Pair<String, String>, Set<APIDescriptor>> apiMap = new HashMap<Pair<String, String>, Set<APIDescriptor>>();
		for (List<APIDescriptor> descriptors : PrivacyAPISummary.sdks.values()) {
			for (APIDescriptor descriptor : descriptors) {
				Pair<String, String> key = new Pair<String, String>(descriptor.apiClazzName, descriptor.apiMethodName);
				if (!apiMap.containsKey(key)) {
					apiMap.put(key, new HashSet<APIDescriptor>());
				}
				apiMap.get(key).add(descriptor);
			}
		}

		// check data flow connections
		// sources are caller privacy apis
		for (int expectedIndex = 0; expectedIndex < expectedAPIConnections.size(); expectedIndex++) {
			Sextet<String, String, String, Set<Pair<String, String>>, Set<Pair<String, String>>, Boolean> sextet = expectedAPIConnections
					.get(expectedIndex);
			if (sextet.getValue5()) {
				continue;
			}

			Set<Pair<String, String>> expectedCallerApis = sextet.getValue3();
			Set<Pair<String, String>> expectedCalleeApis = sextet.getValue4();
			boolean hasDFConnection = false;

			for (Pair<String, String> callerApi : PrivacyAPITracking.dfConnections.keySet()) {
				if (!expectedCallerApis.contains(callerApi)) {
					continue;
				}

				for (Pair<String, String> calleeApi : PrivacyAPITracking.dfConnections.get(callerApi)) {
					if (expectedCalleeApis.contains(calleeApi)) {
						hasDFConnection = true;
						break;
					}
				}
			}

			if (hasDFConnection) {
				expectedAPIConnections.set(expectedIndex,
						new Sextet<String, String, String, Set<Pair<String, String>>, Set<Pair<String, String>>, Boolean>(
								sextet.getValue0(), sextet.getValue1(), sextet.getValue2(), sextet.getValue3(),
								sextet.getValue4(), true));
				Utils.LOGGER.info(String.format("API DF Connection %s %s %s", sextet.getValue0(), sextet.getValue1(),
						sextet.getValue2()));
			}
		}

		// report disconnection;
		for (Sextet<String, String, String, Set<Pair<String, String>>, Set<Pair<String, String>>, Boolean> sextet : expectedAPIConnections) {
			if (sextet.getValue5()) {
				continue;
			}

			JSONObject obj = new JSONObject();
			obj.put("FlawType", "APIDisconnection");
			obj.put("CallerSdkName", sextet.getValue0());
			obj.put("CalleeSdkName", sextet.getValue1());
			obj.put("APIType", sextet.getValue2());
			obj.put("CallerPrivAPIs", sextet.getValue3().toString());
			obj.put("CalleePrivAPIs", sextet.getValue4().toString());
			obj.put("ApkPath", Globals.APK_PATH);
			obj.put("PackageName", Globals.PACKAGE_NAME);

			StringWriter out = new StringWriter();
			obj.write(out);
			Utils.LOGGER.info(out.toString());
		}

		boolean checkDiffusedAPIs = true;
		if (checkDiffusedAPIs) {
			// check for diffused APIs
			for (Sextet<String, String, String, Set<Pair<String, String>>, Set<Pair<String, String>>, Boolean> sextet : expectedAPIConnections) {
				if (sextet.getValue5()) {
					// for all callee privacy APIs that are not called from the designated caller
					// privacy API, we check whether they are called by other methods in the caller
					// package
					// which is a potential indicator of diffused APIs.
					Utils.LOGGER.info(String.format("Reachable %s %s %s, ignoring...", sextet.getValue0(),
							sextet.getValue1(), sextet.getValue2()));
					continue;
				}

				Set<Pair<String, String>> expectedCallerApis = sextet.getValue3();
				Set<Pair<String, String>> expectedCalleeApis = sextet.getValue4();

				// for api disconnection, check diffused delegation
				Set<String> callerPackages = new HashSet<String>();
				for (Pair<String, String> callerApi : expectedCallerApis) {
					String callerClazz = callerApi.getO1();
					callerPackages.add(Utils.getTopDomain(callerClazz));
				}

				for (SootMethod entry : Scene.v().getEntryPoints()) {
					Set<SootMethod> visited = new HashSet<SootMethod>();
					SootMethod caller = entry;
					Vector<SootMethod> path = new Vector<SootMethod>();
					diffusedDelegation(sextet.getValue0(), sextet.getValue1(), Scene.v().getCallGraph(), caller, visited, path,
							expectedCalleeApis, callerPackages);
				}
			}
		}
	}

	private void diffusedDelegation(String callerSdk, String calleeSdk, CallGraph cg, SootMethod current,
			Set<SootMethod> visited, Vector<SootMethod> path, Set<Pair<String, String>> targets,
			Set<String> callerPackages) {
		path.add(current);

		Pair<String, String> currentKey = new Pair<>(current.getDeclaringClass().getName(), current.getName());
		String currentPackage = Utils.getTopDomain(current.getDeclaringClass().getName());
		
		if (targets.contains(currentKey)) {
			boolean initiateFromCallerPackage = false;
			for (SootMethod pathElement : path) {
				boolean pathElementContainInterestingParams = false;

				// without this check, we are experiencing a lot of results.
				// we print a potential problem only if the caller (potential delegation API)
				// contains at least an interesting parameter, such as boolean, etc.
				for (Type type : pathElement.getParameterTypes()) {
					if (Utils.isInterestingTypes(type)) {
						pathElementContainInterestingParams = true;
					}
				}

				if (pathElementContainInterestingParams) {
					for (String callerPackage : callerPackages) {
						if (pathElement.getDeclaringClass().getName().startsWith(callerPackage) &&
								!callerPackage.equals(currentPackage)) { // SDKS such as Firebase and Google Analytics share the same package; we do not report them as diffused delegation.
							initiateFromCallerPackage = true;
						}
					}
				}
			}

			if (initiateFromCallerPackage) {
				JSONArray pathArray = new JSONArray();
				for (SootMethod pathElement : path) {
					pathArray.put(pathElement.getSignature());
				}

				JSONObject obj = new JSONObject();
				obj.put("FlawType", "PotentialDiffusedDelegation");
				obj.put("CallerSdkName", callerSdk);
				obj.put("CalleeSdkName", calleeSdk);
				obj.put("DelegationPath", pathArray);
				obj.put("ApkPath", Globals.APK_PATH);
				obj.put("PackageName", Globals.PACKAGE_NAME);

				StringWriter out = new StringWriter();
				obj.write(out);
				Utils.LOGGER.info(out.toString());
			}
		}

		visited.add(current);

		if (path.size() < Globals.MAX_DEPTH) {
			// Explore the outgoing edges from the current method
			for (Iterator<Edge> it = cg.edgesOutOf(current); it.hasNext();) {
				Edge e = it.next();
				SootMethod callee = e.tgt().method();
				if (!visited.contains(callee)) {
					diffusedDelegation(callerSdk, calleeSdk, cg, callee, visited, path, targets, callerPackages);
				}
			}
		}

		path.remove(path.size() - 1);
	}
}
