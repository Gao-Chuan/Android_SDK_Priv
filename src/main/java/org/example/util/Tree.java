package org.example.util;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

class Node {
    String value;
    int level;
    List<Node> children;

    public Node(String value, int level) {
        this.value = value;
        this.level = level;
        this.children = new ArrayList<>();
    }
}

class Tree {
    Map<String, Node> nodes = new HashMap<>();

    public void addEdge(String parentValue, String childValue, int level) {
        String parentKey = generateKey(parentValue, level - 1);
        String childKey = generateKey(childValue, level);

        Node parent = nodes.computeIfAbsent(parentKey, k -> new Node(parentValue, level - 1));
        Node child = nodes.computeIfAbsent(childKey, k -> new Node(childValue, level));

        parent.children.add(child);
    }

    private String generateKey(String value, int level) {
        return value + ":" + level;
    }

    public void displayTree(String rootValue) {
        displayTreeRecursive(nodes.get(generateKey(rootValue, 0)), 0);
    }

    private void displayTreeRecursive(Node node, int indent) {
        if (node == null) {
            return;
        }

        System.out.println("  ".repeat(indent) + node.value);
        for (Node child : node.children) {
            displayTreeRecursive(child, indent + 1);
        }
    }
}

