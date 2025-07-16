package org.example.check;

import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.toolkits.scalar.Pair;

import java.io.StringWriter;
import java.util.*;

import org.example.util.PrivacyAPISummary;
import org.example.util.Utils;
import org.example.xq.Globals;
import org.json.JSONObject;

import static org.example.util.PrivacyAPISummary.sdks;
import static org.example.util.PrivacyAPISummary.APIDescriptor;

public class MisssingConfiguration {
	public void runAnalysis() {
		// Looping through each sdk in the sdks
		for (Map.Entry<String, List<APIDescriptor>> sdk : sdks.entrySet()) {
			String sdkName = sdk.getKey();
			List<APIDescriptor> apiDescriptors = sdk.getValue();

			Map<Pair<String, String>, Set<String>> privMethodType = new HashMap<Pair<String, String>, Set<String>>();
			// Looping through each APIDescriptor in the list
			for (APIDescriptor apiDescriptor : apiDescriptors) {
				if (apiDescriptor.apiType != PrivacyAPISummary.API_TYPE_INIT) {
					Pair<String, String> privMethod = new Pair<String, String>(apiDescriptor.apiClazzName,
							apiDescriptor.apiMethodName);
					if (!privMethodType.containsKey(privMethod)) {
						privMethodType.put(privMethod, new HashSet<String>());
					}
					privMethodType.get(privMethod).add(apiDescriptor.apiType);
				}
			}

			for (APIDescriptor apiDescriptor : apiDescriptors) {
				if (apiDescriptor.apiType != PrivacyAPISummary.API_TYPE_INIT) {
					continue;
				}

				String clazzNm = apiDescriptor.apiClazzName;
				String methodNm = apiDescriptor.apiMethodName;
				// if current class name or method name is null, continue to next api.
				if (null == clazzNm || null == methodNm) {
					continue;
				}

				try {
					List<SootMethod> methods = Utils.findMethod(clazzNm, methodNm);
					// if current api can't be found in the apk, continue to next api
					if (null == methods) {
						continue;
					}

					Utils.LOGGER.info(String.format("Found init def -- %s.%s", clazzNm, methodNm));
					
					for (Pair<String, String> privMethod : privMethodType.keySet()) {
						checkAPIs(Scene.v().getCallGraph(), clazzNm, methodNm, privMethod.getO1(), privMethod.getO2(),
								sdkName, privMethodType.get(privMethod), 5);
					}
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		}
	}

	/**
	 * Returns all the methods that call the given method within the call graph,
	 * filtering out internal calls.
	 */
	private Set<SootMethod> getCallersOfMethod(CallGraph cg, SootMethod method, String internalClass) {
		// Extract package name by removing the class name
		String packageName = internalClass.substring(0, internalClass.lastIndexOf('.'));

		// Check how many dots the package name has
		int dotCount = (int) packageName.chars().filter(ch -> ch == '.').count();

		// Trim the packageName if it has more than 2 dots
		while (dotCount > 2) {
			packageName = packageName.substring(0, packageName.lastIndexOf('.'));
			dotCount = (int) packageName.chars().filter(ch -> ch == '.').count();
		}

		Set<SootMethod> callers = new HashSet<>();
		Iterator<Edge> edges = cg.edgesInto(method);

		while (edges.hasNext()) {
			Edge edge = edges.next();
			SootMethod srcMethod = edge.src().method();

			// Filtering internal calls
			if (!srcMethod.getDeclaringClass().getName().startsWith(packageName)) {
				callers.add(srcMethod);
			}
		}
		return callers;
	}

	private List<SootMethod> getSortedAncestors(CallGraph cg, SootMethod method, int maxDepth) {
		Map<SootMethod, Integer> ancestorsMap = getAncestors(cg, method, maxDepth);
		List<SootMethod> sortedAncestors = new ArrayList<>(ancestorsMap.keySet());
		sortedAncestors.sort(Comparator.comparingInt(ancestorsMap::get));
		return sortedAncestors;
	}

	/**
	 * Fetch ancestors up to a given depth for a method in a call graph.
	 */
	private Map<SootMethod, Integer> getAncestors(CallGraph cg, SootMethod method, int maxDepth) {
		Map<SootMethod, Integer> ancestors = new HashMap<>();
		fetchAncestors(cg, method, 0, maxDepth, ancestors);
		return ancestors;
	}

	private void fetchAncestors(CallGraph cg, SootMethod method, int currentDepth, int maxDepth,
			Map<SootMethod, Integer> ancestors) {
		if (currentDepth > maxDepth)
			return;

		for (Iterator<Edge> it = cg.edgesInto(method); it.hasNext();) {
			Edge edge = it.next();
			SootMethod srcMethod = edge.src().method();

			// If the method isn't in the ancestors map yet, or if we've found a shorter
			// path to it
			if (!ancestors.containsKey(srcMethod) || ancestors.get(srcMethod) > currentDepth) {
				ancestors.put(srcMethod, currentDepth);
				fetchAncestors(cg, srcMethod, currentDepth + 1, maxDepth, ancestors);
			}
		}
	}

	public List<SootMethod> getMethodsByName(SootClass sc, String methodName) {
		List<SootMethod> methods = new ArrayList<>();
		for (SootMethod m : sc.getMethods()) {
			if (m.getName().equals(methodName)) {
				methods.add(m);
			}
		}
		return methods;
	}

	/**
	 * Traces back the path from a method to its ancestor in the call graph.
	 *
	 * @param cg          The call graph to be analyzed.
	 * @param startMethod The method to start tracing from.
	 * @param ancestor    The ancestor method.
	 * @return List of methods representing the path.
	 */
	private List<SootMethod> tracePathToAncestor(CallGraph cg, SootMethod startMethod, SootMethod ancestor) {
		Map<SootMethod, SootMethod> predecessor = new HashMap<>();
		Set<SootMethod> visited = new HashSet<>();
		Queue<SootMethod> queue = new LinkedList<>();

		queue.add(startMethod);
		visited.add(startMethod);

		while (!queue.isEmpty()) {
			SootMethod current = queue.poll();
			if (current.equals(ancestor)) {
				// Build the path by tracing back through predecessors
				List<SootMethod> path = new ArrayList<>();
				while (current != null) {
					path.add(current);
					current = predecessor.get(current);
				}
				Collections.reverse(path); // Reverse the path to start from the initial method
				return path;
			}

			for (Iterator<Edge> it = cg.edgesInto(current); it.hasNext();) {
				SootMethod srcMethod = it.next().src().method();
				if (!visited.contains(srcMethod)) {
					visited.add(srcMethod);
					queue.add(srcMethod);
					predecessor.put(srcMethod, current);
				}
			}
		}

		return new ArrayList<>(); // Return empty list if no path found
	}

	/**
	 * Checks if methods from two provided classes satisfy specific criteria: 1.
	 * Both methods must be called within the same class. 2. Both methods should
	 * have a common ancestor within the provided maximum call depth.
	 *
	 * @param cg          The call graph to be analyzed.
	 * @param class_init  The class name of the first API.
	 * @param method_init The method name of the first API.
	 * @param class_priv  The class name of the second API.
	 * @param method_priv The method name of the second API.
	 * @param maxDepth    The maximum call depth to check for a common ancestor.
	 */
	public void checkAPIs(CallGraph cg, String class_init, String method_init, String class_priv, String method_priv,
			String sdkName, Set<String> apiTypes, int maxDepth) {
		try {
			// Fetching all overloaded versions of the methods
			List<SootMethod> methodsInit = getMethodsByName(Scene.v().getSootClass(class_init), method_init);
			List<SootMethod> methodsPriv = getMethodsByName(Scene.v().getSootClass(class_priv), method_priv);

			Map<Pair<SootMethod, SootMethod>, Pair<Boolean, Boolean>> initConfigurationMap = new HashMap<Pair<SootMethod, SootMethod>, Pair<Boolean, Boolean>>();

			// Check every combination of method overloads
			for (SootMethod api_init : methodsInit) {
				Set<SootMethod> callersOfInit = getCallersOfMethod(cg, api_init, class_init);
				List<SootMethod> sortedAncestorsInit = getSortedAncestors(cg, api_init, maxDepth);

				for (SootMethod init_caller : callersOfInit) {
					// ignore calls in the same package.
					if (Utils.isSamePackage(api_init.getDeclaringClass().getName(), init_caller.getDeclaringClass().getName())) {
						Utils.LOGGER.info("Same Package " + init_caller.getSignature() + "--" + api_init.getSignature());
						continue;
					} else {
						Utils.LOGGER.info("Caller " + init_caller.getSignature());
					}
					
					Utils.LOGGER.info(String.format("Found init called in %s: %s.%s ", init_caller.getSignature(), class_init, method_init));
					
					// Flags to track if conditions are met
					boolean isPrivCalledNearby = false;
					boolean hasSameAncestor = false;

					for (SootMethod api_priv : methodsPriv) {
						Set<SootMethod> callersOfPriv = getCallersOfMethod(cg, api_priv, class_priv);
						List<SootMethod> sortedAncestorsPriv = getSortedAncestors(cg, api_priv, maxDepth);

						for (SootMethod priv_caller : callersOfPriv) {
							// if (init_caller.getDeclaringClass().equals(priv_caller.getDeclaringClass())) {
							// we check match between a class and its nested class
							// reason: app.elika.baby; admost.sdk.networkadapter.AdMostVungleInitAdapter; Vungle.init and Vungle.updateCCPAStatus
							String init_caller_clazz = init_caller.getDeclaringClass().getName();
							String priv_caller_clazz = priv_caller.getDeclaringClass().getName();
							if (init_caller_clazz.startsWith(priv_caller_clazz) || priv_caller_clazz.startsWith(init_caller_clazz)) {
								isPrivCalledNearby = true;
								Utils.LOGGER.info("Both " + api_init.getSignature() + " and " + api_priv.getSignature()
										+ " are called in class: " + priv_caller.getDeclaringClass().getName());
							}
						}

						// Finding the earliest common ancestor
						SootMethod earliestCommonAncestor = null;
						List<SootMethod> allCommonAncestors = new ArrayList<>();

						for (SootMethod ancestor : sortedAncestorsInit) {
							if (sortedAncestorsPriv.contains(ancestor)) {
								allCommonAncestors.add(ancestor);
								if (earliestCommonAncestor == null) {
									earliestCommonAncestor = ancestor;
									hasSameAncestor = true;
								}
							}
						}

						if (earliestCommonAncestor != null) {
							Utils.LOGGER.info("Earliest common ancestor: " + earliestCommonAncestor.getSignature());
							List<SootMethod> pathToInit = tracePathToAncestor(cg, api_init, earliestCommonAncestor);
							List<SootMethod> pathToPriv = tracePathToAncestor(cg, api_priv, earliestCommonAncestor);
							Utils.LOGGER.info("Path to " + api_init.getSignature() + ": " + pathToInit + " Length: "
									+ pathToInit.size());
							Utils.LOGGER.info("Path to " + api_priv.getSignature() + ": " + pathToPriv + " Length: "
									+ pathToPriv.size());
						}

						// If both conditions are met, break out of loops early
						if (isPrivCalledNearby && hasSameAncestor) {
							break;
						}
					}

					initConfigurationMap.put(new Pair<SootMethod, SootMethod>(init_caller, api_init),
							new Pair<Boolean, Boolean>(isPrivCalledNearby, hasSameAncestor));
				}
			}

			for (Pair<SootMethod, SootMethod> initPair : initConfigurationMap.keySet()) {
				Pair<Boolean, Boolean> configPair = initConfigurationMap.get(initPair);

				if (configPair.getO1() && configPair.getO2()) {
					Utils.LOGGER.info("API connected " + initPair.getO1().getSignature() + " --- "
							+ initPair.getO2().getSignature() + " --- " + class_priv + "." + method_priv);
					continue;
				}

				JSONObject obj = new JSONObject();
				obj.put("FlawType", "MissingConfiguration");
				obj.put("SdkName", sdkName);
				obj.put("InitCaller", initPair.getO1().getSignature());
				obj.put("Init", initPair.getO2().getSignature());
				obj.put("PrivAPIClass", class_priv);
				obj.put("PrivAPIMethod", method_priv);
				obj.put("PrivAPITypes", apiTypes.toString());
				obj.put("isPrivCalledNearby", configPair.getO1());
				obj.put("hasSameAncestor", configPair.getO2());
				obj.put("Reason", methodsPriv.size() < 1? "Legacy SDK that does not define privacy API":"");
				obj.put("ApkPath", Globals.APK_PATH);
				obj.put("PackageName", Globals.PACKAGE_NAME);
				
				StringWriter out = new StringWriter();
				obj.write(out);
				Utils.LOGGER.info(out.toString());
			}
		} catch (soot.ResolutionFailedException e) {
			System.err.println("Failed to resolve a reference: " + e.getMessage());
		} catch (Exception e) {
			// Catch all other exceptions that might occur
			System.err.println("An unexpected error occurred: " + e.getMessage());
		}
	}
}
