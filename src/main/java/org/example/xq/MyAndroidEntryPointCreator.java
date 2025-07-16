package org.example.xq;

import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import soot.Body;
import soot.Local;
import soot.RefType;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.Type;
import soot.Unit;
import soot.Value;
import soot.VoidType;
import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;
import soot.jimple.Jimple;
import soot.jimple.NopStmt;
import soot.jimple.NullConstant;
import soot.jimple.Stmt;
import soot.jimple.infoflow.android.entryPointCreators.AndroidEntryPointCreator;
import soot.jimple.infoflow.android.manifest.IManifestHandler;
import soot.toolkits.scalar.Pair;

public class MyAndroidEntryPointCreator extends AndroidEntryPointCreator {
	private static boolean addEntryInvokes = false;

	public MyAndroidEntryPointCreator(@SuppressWarnings("rawtypes") IManifestHandler manifest,
			Collection<SootClass> components) {
		super(manifest, components);
		this.createEmptyMainMethod();
	}

	@Override
	protected SootMethod createDummyMainInternal() {
		SootMethod ret = super.createDummyMainInternal();
		body.getUnits().removeLast();
		for (Pair<String, String> entry_item : Globals.ENTRY_POINTS) {
			try {
				SootClass c = Scene.v().forceResolve(entry_item.getO1(), SootClass.BODIES);
				c.setApplicationClass();
				SootMethod m = c.getMethod(entry_item.getO2());
				Local localVal = null;
				if (!m.isStatic()) {
					if (localVarsForClasses.containsKey(c)) {
						localVal = localVarsForClasses.get(c);
					} else {
						localVal = generateClassConstructor(c);
						if (localVal == null) {
							System.out.println(String.format("generate class constructor for %s is null", entry_item.getO1()));
							continue;
						}
						localVarsForClasses.put(c, localVal);
					}
				}

				NopStmt afterMethodStmt = Jimple.v().newNopStmt();
				createIfStmt(afterMethodStmt);
				buildMethodCall(m, localVal);
				body.getUnits().add(afterMethodStmt);

				System.out.println(String.format("added entry point: %s %s", entry_item.getO1(), entry_item.getO2()));
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		body.getUnits().add(Jimple.v().newReturnVoidStmt());

		return ret;
	}
}