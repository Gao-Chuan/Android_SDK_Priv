package org.example.xq;

import soot.jimple.Stmt;

public interface ExtraSourceFilter {
	public boolean shouldIgnoreSource(Stmt stmt, String hostClazzName);
}
