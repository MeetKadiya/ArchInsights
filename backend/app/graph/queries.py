"""
Cypher queries catalog for Architectural Anti-Pattern Detection and Graph Analytics.
"""

# 1. Circular Dependencies Detection (Direct and Indirect cycles up to length 6)
DETECT_CIRCULAR_DEPENDENCIES = """
MATCH path = (m1:Module)-[:IMPORTS*2..6]->(m1)
WITH nodes(path) AS cycleNodes, path
// Deduplicate cycles by ensuring the minimum node ID is the head of the path
WITH [n IN cycleNodes | n.id] AS nodeIds, length(path) AS cycleLen, cycleNodes
WITH DISTINCT nodeIds, cycleLen, cycleNodes
RETURN nodeIds AS cycle_path,
       cycleLen AS cycle_length,
       [n IN cycleNodes | n.name] AS module_names
ORDER BY cycleLen ASC
"""

# 2. God Classes (High WMC, high method count, high LOC)
DETECT_GOD_CLASSES = """
MATCH (c:Class)-[:HAS_METHOD]->(m:Function)
WITH c, count(m) AS method_count, sum(m.cyclomatic_complexity) AS total_wmc
WHERE method_count >= 8 OR total_wmc >= 15 OR c.loc >= 200
RETURN c.id AS class_id,
       c.name AS class_name,
       method_count,
       total_wmc,
       c.loc AS lines_of_code
ORDER BY total_wmc DESC
"""

# 3. Tight Coupling / Hub Modules (High Fan-in + Fan-out product)
DETECT_TIGHT_COUPLING = """
MATCH (m:Module)
OPTIONAL MATCH (in_mod:Module)-[:IMPORTS]->(m)
OPTIONAL MATCH (m)-[:IMPORTS]->(out_mod:Module)
WITH m, count(DISTINCT in_mod) AS fan_in, count(DISTINCT out_mod) AS fan_out
WHERE (fan_in + fan_out) >= 6
WITH m, fan_in, fan_out,
     (fan_in * fan_out) AS coupling_factor,
     CASE WHEN (fan_in + fan_out) > 0
          THEN toFloat(fan_out) / (fan_in + fan_out)
          ELSE 0.0 END AS instability
RETURN m.id AS module_id,
       m.name AS module_name,
       fan_in,
       fan_out,
       coupling_factor,
       round(instability * 100) / 100.0 AS instability
ORDER BY coupling_factor DESC
"""

# 4. Shotgun Surgery Suspects (Target functions called across many distinct external modules)
DETECT_SHOTGUN_SURGERY = """
MATCH (target:Function)<-[:CALLS]-(caller:Function)<-[:DEFINES]-(callerMod:Module)
OPTIONAL MATCH (targetParentMod:Module)-[:DEFINES|HAS_METHOD*1..2]->(target)
WHERE targetParentMod IS NULL OR targetParentMod <> callerMod
WITH target, count(DISTINCT callerMod) AS calling_modules_count, collect(DISTINCT callerMod.name) AS caller_modules
WHERE calling_modules_count >= 4
RETURN target.id AS function_id,
       target.name AS function_name,
       calling_modules_count,
       caller_modules
ORDER BY calling_modules_count DESC
"""

# 5. Fetch Full Visualization Graph for D3 (Nodes + Edges)
FETCH_GRAPH_FOR_VISUALIZATION = """
MATCH (n)
WHERE n:Module OR n:Class OR n:Package
OPTIONAL MATCH (n)-[r:IMPORTS|CONTAINS|DEFINES|INHERITS_FROM]->(m)
WHERE m:Module OR m:Class OR m:Package
RETURN collect(DISTINCT {
         id: n.id,
         label: head(labels(n)),
         name: n.name,
         loc: coalesce(n.loc, 10),
         complexity: coalesce(n.cyclomatic_complexity, n.wmc, 1),
         maintainability: coalesce(n.maintainability_index, 80.0)
       }) AS nodes,
       collect(DISTINCT {
         source: n.id,
         target: m.id,
         type: type(r)
       }) AS links
"""

# 6. Martin's Package Coupling Metrics (Ca, Ce, Instability I)
FETCH_PACKAGE_METRICS = """
MATCH (p:Package)-[:CONTAINS]->(m:Module)
OPTIONAL MATCH (ext_mod:Module)-[:IMPORTS]->(m)
  WHERE NOT (p)-[:CONTAINS]->(ext_mod)
OPTIONAL MATCH (m)-[:IMPORTS]->(dep_mod:Module)
  WHERE NOT (p)-[:CONTAINS]->(dep_mod)
WITH p,
     count(DISTINCT m) AS module_count,
     count(DISTINCT ext_mod) AS afferent_coupling,
     count(DISTINCT dep_mod) AS efferent_coupling
WITH p, module_count, afferent_coupling AS Ca, efferent_coupling AS Ce,
     CASE WHEN (afferent_coupling + efferent_coupling) > 0
          THEN toFloat(efferent_coupling) / (afferent_coupling + efferent_coupling)
          ELSE 0.0 END AS instability
RETURN p.id AS package_id,
       p.name AS package_name,
       module_count,
       Ca,
       Ce,
       round(instability * 100) / 100.0 AS instability
ORDER BY instability DESC
"""
