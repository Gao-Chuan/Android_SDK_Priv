package org.example.check;

import java.io.*;
import java.util.*;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.example.util.Utils;
import org.example.xq.Globals;
import org.example.xq.MySetupApplication;
import org.json.JSONArray;
import org.json.JSONObject;
import org.xmlpull.v1.XmlPullParserException;
import soot.*;
import soot.jimple.DefinitionStmt;
import soot.jimple.FieldRef;
import soot.jimple.Stmt;
import soot.jimple.infoflow.InfoflowManager;
import soot.jimple.infoflow.android.InfoflowAndroidConfiguration;
import soot.jimple.infoflow.android.manifest.ProcessManifest;
import soot.jimple.infoflow.data.Abstraction;
import soot.jimple.infoflow.handlers.ResultsAvailableHandler;
import soot.jimple.infoflow.handlers.TaintPropagationHandler;
import soot.jimple.infoflow.results.InfoflowResults;
import soot.jimple.infoflow.results.ResultSinkInfo;
import soot.jimple.infoflow.results.ResultSourceInfo;
import soot.jimple.infoflow.solver.cfg.IInfoflowCFG;
import soot.jimple.infoflow.taintWrappers.EasyTaintWrapper;
import soot.jimple.infoflow.InfoflowConfiguration;
import soot.options.Options;
import soot.toolkits.scalar.Pair;

import static org.example.util.PrivacyAPISummary.sdks;
import static org.example.util.PrivacyAPISummary.APIDescriptor;

/*
 * Tracking privacy APIs for dynamic analysis.
 */
public class PrivacyAPITracking {
	private static final Logger LOGGER = Logger.getLogger(PrivacyAPITracking.class.getName());
	private static Map<Pair<String, Integer>, Object> unsafeValueMap = new HashMap<Pair<String, Integer>, Object>();
	public static Map<Pair<String, String>, Set<Pair<String, String>>> dfConnections = new HashMap<>();
	public static Map<Pair<String, String>, String> apiSdkMap = new HashMap<>();

	public static MySetupApplication setupFlowdroid(Map<Pair<String, String>, Set<String>> stmtSourceSigs)
			throws XmlPullParserException, IOException {
		// get the pkg name and version code
		ProcessManifest processManifest = new ProcessManifest(Globals.APK_PATH);
		String pkg_name = String.valueOf(processManifest.getManifest().getAttribute("package"));
		Pattern p = Pattern.compile("package=\"(.*?)\"");
		Matcher m = p.matcher(pkg_name);
		if (m.find()) {
			pkg_name = m.group(1);
		} else {
			pkg_name = null;
		}
		String version_code = String.valueOf(processManifest.getManifest().getAttribute("versionCode"));
		Pattern p2 = Pattern.compile("versionCode=\"(.*?)\"");
		Matcher m2 = p2.matcher(version_code);
		if (m2.find()) {
			version_code = m2.group(1);
		} else {
			version_code = null;
		}

		// Start to init flowdroid
		G.reset();
		// Use existing call graph.

		File file = new File(Globals.APK_PATH);
		String apkPath = file.getAbsolutePath();

		final InfoflowAndroidConfiguration config = new InfoflowAndroidConfiguration();
		config.getAnalysisFileConfig().setTargetAPKFile(apkPath);
		config.getAnalysisFileConfig().setAndroidPlatformDir(Globals.FRAMEWORK_DIR);
//        To provide single view to analysis
		config.setMergeDexFiles(true);
//        Write analysis result to files for further analysis
		config.setWriteOutputFiles(true);
		config.getAnalysisFileConfig().setSourceSinkFile("res/SharedPreferenceAndNetworkAsSinks.txt");
		config.getCallbackConfig().setEnableCallbacks(true);
		config.setCallgraphAlgorithm(InfoflowConfiguration.CallgraphAlgorithm.CHA);
		config.setDataFlowTimeout(5400);

		Options.v().set_output_format(Options.output_format_jimple);
		Options.v().set_output_dir("sootOutput");
		PackManager.v().writeOutput();
		Options.v().set_whole_program(true);
		Options.v().set_verbose(true);
		Options.v().set_process_multiple_dex(true);
		Options.v().set_allow_phantom_refs(true);
		// Options.v().setPhaseOption("cg.cha", "on");
		// Options.v().setPhaseOption("cg", "all-reachable:true");
		List<String> excludePackagesList = Arrays.asList(new String[] { "androidx.*", "android.*", "com.android.*" });
		Options.v().set_exclude(excludePackagesList);
		Options.v().set_no_bodies_for_excluded(true);
//      Less debug info
		Scene.v().loadNecessaryClasses();

		// Using the Source custom code here:
		MySetupApplication app = new MySetupApplication(config, new HashSet<>(), new HashSet<>(), stmtSourceSigs);

		EasyTaintWrapper easyTaintWrapper = new EasyTaintWrapper("./EasyTaintWrapperSource.txt");
		app.setTaintWrapper(easyTaintWrapper);

		LOGGER.info("setupFlowdroid Finished!");

		return app;
	}

	public static Map<Pair<String, String>, Set<String>> getSourceParamsMap() {
		Map<Pair<String, String>, Set<String>> stmtSourceSigs = new HashMap<>();
		String parameter_str = ":= @parameter%d:"; // %d is a placeholder for the index of parameter.

		// Looping through each sdk in the sdks
		for (Map.Entry<String, List<APIDescriptor>> sdk : sdks.entrySet()) {
			String sdk_name = sdk.getKey();
			List<APIDescriptor> apiDescriptors = sdk.getValue();

			Utils.LOGGER.info("SDK: " + sdk_name); // Printing the key (SDK name)

			// Looping through each APIDescriptor in the list
			for (APIDescriptor apiDescriptor : apiDescriptors) {
				String clazzNm = apiDescriptor.apiClazzName;
				String methodNm = apiDescriptor.apiMethodName;
				// if current class name or method name is null, continue to next api.
				if (null == clazzNm || null == methodNm || apiDescriptor.ppArgs == null) {
					continue;
				}

				try {
					List<SootMethod> methods = Utils.findMethod(clazzNm, methodNm);
					// if current api can't be found in the apk, continue to next api
					if (null == methods) {
						continue;
					}

					for (SootMethod method : methods) {
						String short_sig = method.getSubSignature();
						
						Pair<String, String> methodKey = new Pair<>(clazzNm, methodNm);
						apiSdkMap.put(methodKey, sdk_name);
						Utils.LOGGER.info(String.format("apiSdkMap: <%s, %s>-->%s", methodKey.getO1(), methodKey.getO2(), sdk_name));
								
						// Checking if any privacy preserving parameter index is greater than the
						// method's parameter count.
						boolean notMatch = apiDescriptor.ppArgs.entrySet().stream()
								.anyMatch(ppArg -> method.getParameterCount() < (ppArg.getKey() + 1));
						// If so, continue to next overload method.
						if (notMatch)
							continue;

						for (Integer ppArgIndex : apiDescriptor.ppArgs.keySet()) {
							unsafeValueMap.put(new Pair<String, Integer>(method.getSignature(), ppArgIndex),
									apiDescriptor.ppArgs.get(ppArgIndex));

							JSONObject obj = new JSONObject();
							obj.put("FlawType", "AllPrivacyAPIsToHook");
							obj.put("PrivAPI", method.getSignature());
							obj.put("PrivAPIParameterIndex", ppArgIndex);
							obj.put("APIType", apiDescriptor.apiType);
							obj.put("UnsafeValue", apiDescriptor.ppArgs.get(ppArgIndex));
							obj.put("ApkPath", Globals.APK_PATH);
							obj.put("PackageName", Globals.PACKAGE_NAME);

							StringWriter out = new StringWriter();
							obj.write(out);
							Utils.LOGGER.info(out.toString());
						}

						Set<String> sourceParams = new HashSet<String>();
						for (Integer paramIndex : apiDescriptor.ppArgs.keySet()) {
							if (Utils.isInterestingTypes(method.getParameterType(paramIndex))) {
								// Why do we check isInterestingTypes here?
								// The input Priv_impl.json defines APIs based on a tuple (class, methodname);
								// this becomes a problem when a method has multiple implementations where the
								// privacy parameters are not in the specified index, leading to error tracking
								// of privacy parameters.
								sourceParams.add(String.format(parameter_str, paramIndex));
							}
						}

						if (sourceParams.size() < 1) {
							continue;
						}

						// Otherwise, add the method and the params index set into the stmtSourceSigs.
						stmtSourceSigs.put(new Pair<>(clazzNm, short_sig), sourceParams);
					}
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		}

		Utils.LOGGER.info("the sources in stmtSourceSigs:>>");
		// Looping through each entry in the stmtSourceSigs map
		for (Map.Entry<Pair<String, String>, Set<String>> entry : stmtSourceSigs.entrySet()) {
			Pair<String, String> pairKey = entry.getKey();
			Set<String> values = entry.getValue();

			// Printing the key and values of each entry
			Utils.LOGGER.info("Key: (" + pairKey.getO1() + ", " + pairKey.getO2() + ")");
			Utils.LOGGER.info("Values: " + values);
		}
		Utils.LOGGER.info("getSourceParamsMap() finish.");

		return stmtSourceSigs;
	}

	public void runAnalysis() throws XmlPullParserException, IOException {
		// Set up and launch Flowdroid analysis with custom modifications
		// Using MySetupApplication to generate the returned SetupApplication.
		Map<Pair<String, String>, Set<String>> stmtSourceSigs = getSourceParamsMap();
		MySetupApplication app = setupFlowdroid(stmtSourceSigs);

		// remove the previous log files
		/*
		 * File file = new File("res/notifyFlowOut.txt"); if (file.exists()) {
		 * file.delete(); }
		 * 
		 * file = new File("res/notifyFlowIn.txt"); if (file.exists()) { file.delete();
		 * }
		 */

		app.setTaintPropagationHandler(new TaintPropagationHandler() {
			@Override
			public void notifyFlowIn(Unit stmt, Abstraction taint, InfoflowManager manager, FlowFunctionType type) {
				/*
				 * String out_str = "\n>>>new in\n" + "stmt:\n"+ stmt.toString() + "\n" +
				 * "current stmt:\n"+ taint.getCurrentStmt() + "\n" + "type:\n"+ type.toString()
				 * + "\n";
				 * 
				 * try { BufferedWriter writer; writer = new BufferedWriter(new
				 * FileWriter("res/notifyFlowIn.txt", true)); writer.write(out_str);
				 * writer.close(); } catch (IOException e) { throw new RuntimeException(e); }
				 */
			}

			@Override
			public Set<Abstraction> notifyFlowOut(Unit stmt, Abstraction d1, Abstraction incoming,
					Set<Abstraction> outgoing, InfoflowManager manager, FlowFunctionType type) {
				for (Abstraction abs : outgoing) {
					if (abs.equals(incoming)) {
						continue;
					}

					if (stmt instanceof DefinitionStmt) {
						SootMethod currentMethod = manager.getICFG().getMethodOf(stmt);
						Pair<String, String> currentKey = new Pair<>(currentMethod.getDeclaringClass().getName(), currentMethod.getName());
						
						if (apiSdkMap.containsKey(currentKey)) {
							List<Pair<SootMethod, Stmt>> reversePathToStmt = new ArrayList<>();
							reversePathToStmt
									.add(new Pair<SootMethod, Stmt>(currentMethod, (Stmt) stmt));
							
							boolean isDummyMainInPath = false;

							Abstraction pd = abs.getPredecessor();
							while (pd != null) {
								Stmt predStmt = pd.getCurrentStmt();
								if (predStmt != null) {
									SootMethod predMethod = manager.getICFG().getMethodOf(predStmt);

									if (predMethod.getDeclaringClass().getName().contains("dummyMainClass")) {
										isDummyMainInPath = true;
									}

									reversePathToStmt.add(new Pair<SootMethod, Stmt>(predMethod, predStmt));
								}
								pd = pd.getPredecessor();
							}

							if (isDummyMainInPath) {
								continue;
							}

							if (reversePathToStmt.size() < 2) {
								continue;
							}
							
							SootMethod srcMethod = reversePathToStmt.get(reversePathToStmt.size() - 1).getO1();
							Pair<String, String> srcKey = new Pair<>(srcMethod.getDeclaringClass().getName(), srcMethod.getName());
							//remember some information for APIDisconnection analysis
							if (apiSdkMap.containsKey(currentKey) && 
									apiSdkMap.containsKey(srcKey) && 
									apiSdkMap.get(srcKey) != apiSdkMap.get(currentKey)) {
								Utils.LOGGER.info(String.format("Found DF Connection: <%s, %s, %s> --- <%s, %s, %s>", 
										apiSdkMap.get(srcKey), srcKey.getO1(), srcKey.getO2(),
										apiSdkMap.get(currentKey), currentKey.getO1(), currentKey.getO2()));
								dfConnections.computeIfAbsent(srcKey, k -> new HashSet<>()).add(currentKey);
							}
						}
						
						Value lhs = ((DefinitionStmt) stmt).getLeftOp();
						if (lhs instanceof FieldRef) {
							SootField lhsField = ((FieldRef) lhs).getField();

							List<Pair<SootMethod, Stmt>> reversePathToStmt = new ArrayList<>();
							reversePathToStmt
									.add(new Pair<SootMethod, Stmt>(currentMethod, (Stmt) stmt));

							// the reason we need: FlowDroid builds dummymain function which would also be
							// included in taint propagation.
							// we can safely ignore these assuming the path between privacy api and its
							// field does not go through implicit APIs.
							boolean isDummyMainInPath = false;

							Abstraction pd = abs.getPredecessor();
							while (pd != null) {
								Stmt predStmt = pd.getCurrentStmt();
								if (predStmt != null) {
									SootMethod predMethod = manager.getICFG().getMethodOf(predStmt);

									if (predMethod.getDeclaringClass().getName().contains("dummyMainClass")) {
										isDummyMainInPath = true;
									}

									reversePathToStmt.add(new Pair<SootMethod, Stmt>(predMethod, predStmt));
								}
								pd = pd.getPredecessor();
							}

							if (isDummyMainInPath) {
								continue;
							}

							if (reversePathToStmt.size() < 2) {
								continue;
							}

							Stmt srcStmt = reversePathToStmt.get(reversePathToStmt.size() - 1).getO2();
							SootMethod srcMethod = reversePathToStmt.get(reversePathToStmt.size() - 1).getO1();
							
							Type srcType = null;
							Object unsafeValue = null;
							if (srcStmt instanceof DefinitionStmt) {
								srcType = ((DefinitionStmt) srcStmt).getLeftOp().getType();

								int argIndex = 0;
								if (srcStmt.toString().contains("@parameter0")) {
									argIndex = 0;
								} else if (srcStmt.toString().contains("@parameter1")) {
									argIndex = 1;
								} else if (srcStmt.toString().contains("@parameter2")) {
									argIndex = 2;
								} else if (srcStmt.toString().contains("@parameter3")) {
									argIndex = 3;
								} else if (srcStmt.toString().contains("@parameter4")) {
									argIndex = 4;
								} else if (srcStmt.toString().contains("@parameter5")) {
									argIndex = 5;
								}

								unsafeValue = unsafeValueMap
										.get(new Pair<String, Integer>(srcMethod.getSignature(), argIndex));
							}

							// we assume that privacy API only changes fields in the same package; this to
							// avoid the large number of fields.
							if (Utils.isSamePackage(srcMethod.getDeclaringClass().getName(),
									lhsField.getDeclaringClass().getName())) {

								// below is a filter on the fields; we assume that privacy api arguments are
								// stored in basic types, similar to the input.
								boolean isBasicType = (lhsField.getType().equals(srcType)
										|| Utils.isInterestingTypes(lhsField.getType()))
										&& reversePathToStmt.size() < Globals.MAX_DEPTH;

								if (isBasicType) {
									JSONObject obj = new JSONObject();
									obj.put("FlawType", "ForDynamicAnalysisHookValue");
									obj.put("PrivAPI", reversePathToStmt.get(reversePathToStmt.size() - 1).getO1());
									obj.put("PrivAPIParameter",
											reversePathToStmt.get(reversePathToStmt.size() - 1).getO2());
									obj.put("HookType", "Field");
									obj.put("FieldRef", lhsField.getSignature());
									obj.put("UnsafeValue", unsafeValue);
									obj.put("IsStaticField", lhsField.isStatic());

									JSONArray pathArray = new JSONArray();
									for (int pathIndex = reversePathToStmt.size() - 1; pathIndex >= 0; --pathIndex) {
										JSONObject pathObj = new JSONObject();
										pathObj.put("HostingMethod", reversePathToStmt.get(pathIndex).getO1());
										pathObj.put("Stmt", reversePathToStmt.get(pathIndex).getO2());
										pathArray.put(pathObj);
									}
									obj.put("TaintPath", pathArray);
									obj.put("ApkPath", Globals.APK_PATH);
									obj.put("PackageName", Globals.PACKAGE_NAME);

									StringWriter out = new StringWriter();
									obj.write(out);
									Utils.LOGGER.info(out.toString());
								} 
								
								// this log is added for the purpose of detecting the below case:
								// two privacy APIs write to the same field, which leads to override (or exclusion) of one law over another.
								JSONObject obj = new JSONObject();
								obj.put("FlawType", "CrossPrivacyAPIOverride");
								obj.put("PrivAPI", reversePathToStmt.get(reversePathToStmt.size() - 1).getO1());
								obj.put("PrivAPIParameter",
										reversePathToStmt.get(reversePathToStmt.size() - 1).getO2());
								obj.put("FieldRef", lhsField.getSignature());
								obj.put("UnsafeValue", unsafeValue);
								obj.put("IsStaticField", lhsField.isStatic());

								JSONArray pathArray = new JSONArray();
								for (int pathIndex = reversePathToStmt.size() - 1; pathIndex >= 0; --pathIndex) {
									JSONObject pathObj = new JSONObject();
									pathObj.put("HostingMethod", reversePathToStmt.get(pathIndex).getO1());
									pathObj.put("Stmt", reversePathToStmt.get(pathIndex).getO2());
									pathArray.put(pathObj);
								}
								obj.put("TaintPath", pathArray);
								obj.put("ApkPath", Globals.APK_PATH);
								obj.put("PackageName", Globals.PACKAGE_NAME);

								StringWriter out = new StringWriter();
								obj.write(out);
								Utils.LOGGER.info(out.toString());
								
								//else {
								//	obj.put("FlawType", "ForDynamicAnalysisHookValue-Debug-Purpose");
								//}
							}
						}
					}
				}
				return outgoing;

				/*
				 * String out_str = "\n>>>new out" + "\n" + "stmt:\n" + stmt.toString() + "\n" +
				 * "d1:\n" + d1.toString() + "\n" + "incoming access path:\n" +
				 * incoming.getAccessPath().toString() + "\n";
				 * 
				 * for (Abstraction abs: outgoing) { out_str += "outgoing:\n"; AccessPath ap =
				 * abs.getAccessPath(); if (ap == null){ out_str += "null\n"; } else{ out_str +=
				 * abs.getCurrentStmt() + "\n"; } out_str += "path_length:>>  " +
				 * abs.getPathLength() + "\n"; out_str += "backward_path:>>" + "\n"; Abstraction
				 * pd = abs.getPredecessor(); int i = 1; while (pd != null){ out_str += i +
				 * "    "; out_str += pd.getCurrentStmt() + "\n"; Stmt curstmt =
				 * pd.getCurrentStmt(); if (curstmt != null){ out_str += "        inside:>>" +
				 * manager.getICFG().getMethodOf(curstmt).getSignature() + "\n"; } pd =
				 * pd.getPredecessor(); i += 1; } }
				 * 
				 * // out_str += "incoming neibours:\n"; // Set<Abstraction> neibours =
				 * incoming.getNeighbors(); // if(neibours == null){ // out_str += "null\n"; //
				 * } else{ // for (Abstraction neibour: neibours){ // out_str += neibour + "\n";
				 * // } // }
				 * 
				 * out_str += "Signature:\n" +
				 * manager.getICFG().getMethodOf(stmt).getSignature() + "\n"; out_str = out_str
				 * + "type:\n" + type.toString() + "\n";
				 * 
				 * try { BufferedWriter writer; writer = new BufferedWriter(new
				 * FileWriter("res/notifyFlowOut.txt", true)); writer.write(out_str);
				 * writer.close(); } catch (IOException e) { throw new RuntimeException(e); }
				 * return outgoing;
				 */
			}
		});

		app.addResultsAvailableHandler(new ResultsAvailableHandler() {
			@Override
			public void onResultsAvailable(IInfoflowCFG cfg, InfoflowResults results) {
				// TODO Auto-generated method stub
				if (results.getResults() != null) {
					for (ResultSinkInfo sink : results.getResults().keySet()) {
						// Get the sink method
						Stmt sinkStmt = sink.getStmt();
						if (sinkStmt.containsInvokeExpr()) {
							String sinkMethod = sinkStmt.getInvokeExpr().getMethod().getSignature();
							// Get all source methods connected to this sink
							Set<ResultSourceInfo> sourceInfos = results.getResults().get(sink);
							for (ResultSourceInfo sourceInfo : sourceInfos) {
								Stmt sourceStmt = sourceInfo.getStmt();

								JSONObject obj = new JSONObject();
								obj.put("FlawType", "ForDynamicAnalysisHookValue");
								obj.put("PrivAPI", cfg.getMethodOf(sourceStmt).getSignature());
								obj.put("PrivAPIParameter", sourceStmt.toString());
								obj.put("HookType", "API");
								obj.put("SinkSignature", sinkMethod);
								obj.put("SinkStmt", sinkStmt.toString());

								JSONArray pathArray = new JSONArray();
								obj.put("TaintPath", pathArray);
								obj.put("ApkPath", Globals.APK_PATH);
								obj.put("PackageName", Globals.PACKAGE_NAME);

								StringWriter out = new StringWriter();
								obj.write(out);
								Utils.LOGGER.info(out.toString());

								/*
								 * if (sourceStmt.containsInvokeExpr()) { // Check if the statement contains an
								 * invoke expression String sourceMethod =
								 * sourceStmt.getInvokeExpr().getMethod().getSignature();
								 * Utils.LOGGER.info("Source: " + sourceMethod); } else { Utils.LOGGER.info(
								 * "Warning: Source statement does not contain an invoke expression: " +
								 * sourceStmt); } // Process the source and sink method signatures // Here you
								 * can print, log, or further analyze the data flow Utils.LOGGER.info("Sink: " +
								 * sinkMethod);
								 */
							}
						} else {
							Utils.LOGGER
									.info("Warning: Sink statement does not contain an invoke expression: " + sinkStmt);
						}
					}
				} else {
					Utils.LOGGER.info("No results found.");
				}
			}
		});

		app.runInfoflow();

		LOGGER.info("Main ends!");
	}
}