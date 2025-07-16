package org.example.xq;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.example.util.Utils;
import org.example.util.PrivacyAPISummary;
import org.example.util.PrivacyAPISummary.APIDescriptor;

import soot.Body;
import soot.G;
import soot.Main;
import soot.PackManager;
import soot.RefType;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.Transform;
import soot.Type;
import soot.Unit;
import soot.ValueBox;
import soot.jimple.InvokeStmt;
import soot.jimple.infoflow.InfoflowConfiguration;
import soot.jimple.infoflow.InfoflowConfiguration.CallgraphAlgorithm;
import soot.jimple.infoflow.android.InfoflowAndroidConfiguration;
import soot.jimple.infoflow.android.SetupApplication;
import soot.jimple.infoflow.android.config.SootConfigForAndroid;
import soot.jimple.infoflow.cfg.LibraryClassPatcher;
import soot.jimple.infoflow.handlers.ResultsAvailableHandler;
import soot.jimple.infoflow.handlers.TaintPropagationHandler;
import soot.jimple.infoflow.results.InfoflowResults;
import soot.jimple.infoflow.taintWrappers.EasyTaintWrapper;
import soot.jimple.infoflow.taintWrappers.IdentityTaintWrapper;
import soot.jimple.infoflow.taintWrappers.TaintWrapperSet;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.jimple.toolkits.callgraph.ReachableMethods;
import soot.options.Options;
import soot.toolkits.scalar.Pair;

public class AnalysisAPIs {
	/*
	 * use "uncalled methods in registered components" as entry points
	 */
	public static void setupDefaultEntries() {
		Globals.EXTRA_ENTRY_POINT_FILTER = new ExtraEntryPointFilter() {
			@Override
			public boolean shouldIgnoreEntryPoint(Pair<String, String> entry) {
				String entryClazz = entry.getO1();
				String entryMethod = entry.getO2();

				if (entryClazz.contains("$") || entryMethod.contains("$") || entryMethod.contains("<")
						|| entryClazz.lastIndexOf('.') + 3 >= entryClazz.length()
						|| entryMethod.lastIndexOf('(') <= entryMethod.lastIndexOf(' ') + 3) {
					return true;
				}

				// excludes
				String[] excludes = new String[] { "kotlin.", "kotlinx.", "android.", "androidx.", "org.",
						"com.google.", "okhttp3.", "org.ksoap2x.", "com.squareup.", "retrofit.", "com.ibm.",
						"org.eclipse.paho.", "org.ksoap2.", "retrofit2.", "com.loopj.", "io.fabric.",
						"org.springframework.", "com.octo.android.", "com.android.volley.", "com.amazonaws.",
						"com.aliyun.", "com.alibaba.", "com.microsoft.", "com.azure.", "okio." };
				for (String exclude : excludes) {
					if (entryClazz.startsWith(exclude)) {
						return true;
					}
				}

				return false;
			}
		};

		DefaultEntryPointCollector defaultEntryPointCollector = new DefaultEntryPointCollector();
		runCustomPack("jtp",
				new Transform[] { new Transform("jtp.defaultEntryPointCollector", defaultEntryPointCollector) });
		Set<Pair<String, String>> uncalled = defaultEntryPointCollector.getAppUncalledMethods();
		
		for (Pair<String, String> entry : uncalled) {
			if (!Globals.EXTRA_ENTRY_POINT_FILTER.shouldIgnoreEntryPoint(entry)) {
				Globals.ENTRY_POINTS.add(entry);
			}
		}
		
		// add all methods in the privacy api summary as entries as well
		for (List<APIDescriptor> descriptorList : PrivacyAPISummary.sdks.values()) {
			for (APIDescriptor descriptor : descriptorList) {
				String className = descriptor.apiClazzName;
				String methodName = descriptor.apiMethodName;
				
				if (className == null || methodName == null) {
					continue;
				}
				
				try {
					SootClass sootClazz = Scene.v().loadClassAndSupport(className);
					
					for (SootMethod sootMethod : sootClazz.getMethods()) {
						if (methodName.equals(sootMethod.getName())) {
							Globals.ENTRY_POINTS.add(new Pair<String, String>(className, sootMethod.getSubSignature()));
						}
					}
				} catch (Exception e) {
					e.printStackTrace();
				}
				
			}
		}
	}
	
	/*
	 * use flowdroid to find reachable methods
	 */
	public static void buildCallGraphWithFlowDroid() {
		G.reset();
		InfoflowAndroidConfiguration config = new InfoflowAndroidConfiguration();
		config.getAnalysisFileConfig().setTargetAPKFile(Globals.APK_PATH);
		config.getAnalysisFileConfig().setAndroidPlatformDir(Globals.FRAMEWORK_DIR);
		config.setTaintAnalysisEnabled(false);

		Set<String> unused = new HashSet<String>();
		SetupApplication analyzer = new MySetupApplication(config, unused, unused, new HashMap<>());

		SootConfigForAndroid sootConf = new SootConfigForAndroid() {
			@Override
			public void setSootOptions(Options options, InfoflowConfiguration config) {
				super.setSootOptions(options, config);

				options.set_process_multiple_dex(true);
				options.set_output_format(Options.output_format_jimple);
				options.set_force_overwrite(true);
				options.set_output_dir(Globals.JIMPLE_SUBDIR);
			}
		};

		analyzer.setSootConfig(sootConf);
		analyzer.constructCallgraph();

		ReachableMethods rm = Scene.v().getReachableMethods();
		for (Iterator rmIterator = Scene.v().getReachableMethods().listener(); rmIterator.hasNext();) {
			SootMethod m = (SootMethod) rmIterator.next();
			Globals.REACHABLE_METHODS.add(m.getSignature());
		}
	}
	
	public static void buildCallGraphWithSystemPatcher() {
		long startTime = 0;
		long endTime = 0;
		startTime = System.currentTimeMillis();
		
		Utils.LOGGER.info("Initializing Soot...");

		// Clean up any old Soot instance we may have
		G.reset();

		Options.v().set_no_bodies_for_excluded(true);
		Options.v().set_allow_phantom_refs(true);
		Options.v().set_output_format(Options.output_format_none);
		Options.v().set_whole_program(true);
		Options.v().set_process_dir(Collections.singletonList(Globals.APK_PATH));
		Options.v().set_android_jars(Globals.FRAMEWORK_DIR);
		Options.v().set_src_prec(Options.src_prec_apk);
		Options.v().set_keep_offset(false);
		Options.v().set_throw_analysis(Options.throw_analysis_dalvik);
		Options.v().set_process_multiple_dex(true);
		Options.v().set_ignore_resolution_errors(true);
		Options.v().set_exclude(Globals.EXCLUDED_ANDROID);

		Main.v().autoSetOptions();
		//Options.v().setPhaseOption("cg.spark", "on");
		
		// Load whatever we need
		Utils.LOGGER.info("Loading dex files...");
		Scene.v().loadNecessaryClasses();

		// Make sure that we have valid Jimple bodies
		PackManager.v().getPack("wjpp").apply();

		// Patch the callgraph to support additional edges. We do this now,
		// because during callback discovery, the context-insensitive callgraph
		// algorithm would flood us with invalid edges.
		LibraryClassPatcher patcher = new LibraryClassPatcher();
		patcher.patchLibraries();
		
		List<SootMethod> entryPoints = new ArrayList<SootMethod>();

		for (Pair<String, String> entry : Globals.ENTRY_POINTS) {
			String entryClazz = entry.getO1();
			String entryMethod = entry.getO2();

			try {
				SootClass sootClazz = Scene.v().loadClassAndSupport(entryClazz);
				SootMethod sootMethod = sootClazz.getMethod(entryMethod);
				entryPoints.add(sootMethod);
				//Utils.LOGGER.info(String.format("Entry: <%s: %s>", entry.getO1(), entry.getO2()));
			} catch (Exception e) {
				e.printStackTrace();
			}
		}

		Scene.v().setEntryPoints(entryPoints);
		
		Utils.LOGGER.info("Constructing the callgraph...");
		PackManager.v().getPack("cg").apply();
		
		ReachableMethods rm = Scene.v().getReachableMethods();
		for (Iterator rmIterator = Scene.v().getReachableMethods().listener(); rmIterator.hasNext();) {
			SootMethod m = (SootMethod) rmIterator.next();
			Globals.REACHABLE_METHODS.add(m.getSignature());
		}

		endTime = System.currentTimeMillis();
		System.out.println(String.format("cg construction costs %d seconds", (endTime - startTime) / 1000));
	}
	
	public static void postProcessCallGraph() {
		CallGraph cg = Scene.v().getCallGraph();
		ReachableMethods rMethods = Scene.v().getReachableMethods();
		for (Iterator rmIterator = rMethods.listener(); rmIterator.hasNext();) {
			SootMethod currentMethod = (SootMethod) rmIterator.next();
			
			Map<String, Set<String>> subSignatureToSignatures = new HashMap<>();
			Map<String, Set<Edge>> subSignatureToEdges = new HashMap<>();
			
			for (Iterator<Edge> it = cg.edgesOutOf(currentMethod); it.hasNext();) {
				Edge edge = it.next();
				SootMethod target = edge.tgt();
				String subSignature = target.getSubSignature();
				
				if (subSignature.contains("<init>") || subSignature.contains("<clinit>")) {
					continue;
				}
				subSignatureToSignatures.computeIfAbsent(subSignature, k -> new HashSet<>()).add(target.getSignature());
				subSignatureToEdges.computeIfAbsent(subSignature, k -> new HashSet<>()).add(edge);
			}
			
			boolean hasInaccurateEdges = false;
			for (String subSignature : subSignatureToSignatures.keySet()) {
				if (subSignatureToSignatures.get(subSignature).size() >= 10) {
					hasInaccurateEdges = true;
					break;
				}
			}
			
			if (!hasInaccurateEdges) {
				continue;
			}
			
			Set<SootClass> associatedClasses = new HashSet<>();
			if (currentMethod.hasActiveBody()) {
				Body body = currentMethod.getActiveBody();
				
				for (Unit unit : body.getUnits()) {
					for (ValueBox vb : unit.getUseAndDefBoxes()) {
						Type type = vb.getValue().getType();
						if (type instanceof RefType) {
							SootClass classOfType = ((RefType) type).getSootClass();
							
							if (classOfType.isApplicationClass()) {
								associatedClasses.add(classOfType);
							}
						}
					}
				}
			}
			
			for (String subSignature : subSignatureToSignatures.keySet()) {
				if (subSignatureToSignatures.get(subSignature).size() < 10) {
					continue;
				}
				
				Set<Edge> inaccurateEdges = subSignatureToEdges.get(subSignature);
				Set<Edge> edgesRemain = new HashSet<Edge>();
				for (Edge edge: inaccurateEdges) {
					SootMethod target = edge.tgt();
					SootClass targetClazz = target.getDeclaringClass();
					
					if (target.isAbstract() || targetClazz.isAbstract() || !targetClazz.isApplicationClass()) {
						continue;
					}
					
					if (associatedClasses.contains(targetClazz)) {
						edgesRemain.add(edge);
					}
				}
				
				// remove those less related edges
				if (edgesRemain.size() > 0) {
					for (Edge edge : inaccurateEdges) {
						if (edgesRemain.contains(edge)) {
							//Utils.LOGGER.info(String.format("\t%s-->%s", currentMethod.getSignature(), edge.tgt().getSignature()));
						} else {
							//Utils.LOGGER.info(String.format("\t%s-/->%s", currentMethod.getSignature(), edge.tgt().getSignature()));
							cg.removeEdge(edge);
						}
					}
				} else {
					// do a reasonable guess
					for (SootClass clazz : associatedClasses) {
						if (clazz.isAbstract()) {
							continue;
						}
						
						try {
							SootMethod potentialMethod = clazz.getMethod(subSignature);
							if (potentialMethod != null && !potentialMethod.isAbstract()) {
								Edge potentialEdge = new Edge(currentMethod, inaccurateEdges.iterator().next().srcUnit(), potentialMethod, inaccurateEdges.iterator().next().kind());
								cg.addEdge(potentialEdge);
								edgesRemain.add(potentialEdge);
								//Utils.LOGGER.info(String.format("Add edge: %s-->%s", currentMethod.getSignature(), potentialMethod.getSignature()));
							}
						} catch (Exception e) {
							e.printStackTrace();
						}
					}
					
					if (edgesRemain.size() < 1) {
						for (Edge edge : inaccurateEdges) {
							boolean shouldRemove = true;
							
							SootMethod target = edge.tgt();
							SootClass targetClazz = target.getDeclaringClass();
							
							for (SootClass associatedClazz : associatedClasses) {
								if (Utils.isSubclassOf(targetClazz, associatedClazz) || 
										(associatedClazz.isInterface() && Utils.implementsInterface(targetClazz, associatedClazz))) {
									shouldRemove = false;
								}
							}
							
							if (shouldRemove) {
								cg.removeEdge(edge);
								//Utils.LOGGER.info(String.format("Remove edge: %s-->%s", currentMethod.getSignature(), target.getSignature()));
							}
						}
					}
				}
			}
		}
	}
	
	/*
	 * use soot to find reachable methods
	 */
	public static void buildCallGraphWithSoot() {
		long startTime = 0;
		long endTime = 0;
		startTime = System.currentTimeMillis();

		G.reset();
		Options.v().set_src_prec(Options.src_prec_apk);
		Options.v().set_process_dir(Collections.singletonList(Globals.APK_PATH));
		Options.v().set_android_jars(Globals.FRAMEWORK_DIR);
		Options.v().set_whole_program(true);
		Options.v().set_allow_phantom_refs(true);
		Options.v().set_output_format(Options.output_format_none);
		Options.v().set_process_multiple_dex(true);
		Options.v().set_exclude(Globals.EXCLUDED_ANDROID);
		Options.v().set_no_bodies_for_excluded(true);

		List<SootMethod> entryPoints = new ArrayList<SootMethod>();

		for (Pair<String, String> entry : Globals.ENTRY_POINTS) {
			String entryClazz = entry.getO1();
			String entryMethod = entry.getO2();

			try {
				SootClass sootClazz = Scene.v().loadClassAndSupport(entryClazz);
				SootMethod sootMethod = sootClazz.getMethod(entryMethod);
				entryPoints.add(sootMethod);
				//Utils.LOGGER.info(String.format("Entry: <%s: %s>", entry.getO1(), entry.getO2()));
			} catch (Exception e) {
				e.printStackTrace();
			}
		}

		Scene.v().setEntryPoints(entryPoints);

		Scene.v().loadNecessaryClasses();
		PackManager.v().runPacks();

		ReachableMethods rm = Scene.v().getReachableMethods();
		for (Iterator rmIterator = Scene.v().getReachableMethods().listener(); rmIterator.hasNext();) {
			SootMethod m = (SootMethod) rmIterator.next();
			Globals.REACHABLE_METHODS.add(m.getSignature());
		}

		endTime = System.currentTimeMillis();
		System.out.println(String.format("cg construction costs %d seconds", (endTime - startTime) / 1000));
	}

	public static void runCustomPack(String packName, Transform[] transforms) {
		long startTime = 0;
		long endTime = 0;
		startTime = System.currentTimeMillis();

		G.reset();
		for (Transform transform : transforms) {
			PackManager.v().getPack(packName).add(transform);
		}
		Options.v().set_src_prec(soot.options.Options.src_prec_apk);
		Options.v().set_process_dir(Collections.singletonList(Globals.APK_PATH));
		Options.v().set_android_jars(Globals.FRAMEWORK_DIR);
		Options.v().set_whole_program(true);
		Options.v().set_allow_phantom_refs(true);
		Options.v().set_force_overwrite(true);
		Options.v().set_process_multiple_dex(true);
		Options.v().set_exclude(Globals.EXCLUDED_ANDROID);
		Options.v().set_no_bodies_for_excluded(true);
		Options.v().set_output_dir(Globals.JIMPLE_SUBDIR);
		Options.v().set_no_writeout_body_releasing(true);

		soot.Main.main(new String[] { "-output-format", "J" });

		endTime = System.currentTimeMillis();
		System.out.println(String.format("Pack %s costs %d seconds", packName, (endTime - startTime) / 1000));
	}

	public static InfoflowResults taintPropagation(Collection<String> srcAPIs, Collection<String> dstAPIs,
			TaintPropagationHandler taintPropHandler, Set<String> stringSourcesSigs, Set<String> fieldSourceSigs,
			ResultsAvailableHandler handler) {
		InfoflowResults results = null;

		long startTime = 0;
		long endTime = 0;
		startTime = System.currentTimeMillis();

		try {
			FileWriter fileWriter = new FileWriter(Globals.SRC_SINK_FILE);
			PrintWriter printWriter = new PrintWriter(fileWriter);
			for (String sc : srcAPIs) {
				printWriter.printf("%s -> _SOURCE_\n", sc);
			}
			for (String sk : dstAPIs) {
				printWriter.printf("%s -> _SINK_\n", sk);
			}
			printWriter.close();
		} catch (Exception e) {
			e.printStackTrace();
		}

		try {
			G.reset();
			InfoflowAndroidConfiguration config = new InfoflowAndroidConfiguration();
			config.getAnalysisFileConfig().setTargetAPKFile(Globals.APK_PATH);
			config.getAnalysisFileConfig().setAndroidPlatformDir(Globals.FRAMEWORK_DIR);
			config.getAnalysisFileConfig().setSourceSinkFile(Globals.SRC_SINK_FILE);
			// config.setImplicitFlowMode(ImplicitFlowMode.AllImplicitFlows);
			// config.getAccessPathConfiguration().setAccessPathLength(4);

			SetupApplication analyzer = new MySetupApplication(config, stringSourcesSigs, fieldSourceSigs,
					new HashMap<>());

			if (taintPropHandler != null) {
				analyzer.setTaintPropagationHandler(taintPropHandler);
			}

			SootConfigForAndroid sootConf = new SootConfigForAndroid() {
				@Override
				public void setSootOptions(Options options, InfoflowConfiguration config) {
					super.setSootOptions(options, config);
					options.set_process_multiple_dex(true);
					options.set_exclude(Globals.EXCLUDED_ANDROID);
					options.set_no_bodies_for_excluded(true);
					options.set_output_format(Options.output_format_jimple);
					options.set_force_overwrite(true);
					options.set_output_dir(Globals.JIMPLE_SUBDIR);
					Options.v().set_no_writeout_body_releasing(true);
				}
			};

			analyzer.setSootConfig(sootConf);

			/*
			 * Here we use EasyTaintWrapper by default. This may lose track of some data
			 * flows. Check out the other taint wrappers in the following link or implement
			 * our own if necessary.
			 * 
			 * https://github.com/secure-software-engineering/FlowDroid/tree/develop/soot-
			 * infoflow/src/soot/jimple/infoflow/taintWrappers
			 */
			TaintWrapperSet wrapperSet = new TaintWrapperSet();
			wrapperSet.addWrapper(new IdentityTaintWrapper());
			EasyTaintWrapper easyTaintWrapper = new EasyTaintWrapper(
					new File(Globals.CONFIG_DIR + "EasyTaintWrapperSource.txt"));
			wrapperSet.addWrapper(easyTaintWrapper);
			analyzer.setTaintWrapper(wrapperSet);

			if (handler != null) {
				analyzer.addResultsAvailableHandler(handler);
			}
			results = analyzer.runInfoflow();
		} catch (Exception e) {
			e.printStackTrace();
		}

		endTime = System.currentTimeMillis();
		System.out.println(String.format("Taint propagation costs %d seconds", (endTime - startTime) / 1000));
		return results;
	}
}
