import os
import json
from typing import List, Optional, Dict, Any
from pydantic import BaseModel

from app.parser.models import CodebaseGraph, GraphNode
from app.analysis.anti_patterns import AntiPatternReport
from app.analysis.metrics_engine import ArchitecturalDebtSummary
from app.analysis.refactoring import RefactoringPlan


class AiActionItem(BaseModel):
    id: str
    title: str
    target_id: str
    target_name: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    difficulty: str  # e.g., "Easy (15 mins)", "Medium (45 mins)", "Advanced"
    debt_reduction_pct: int
    plain_english_summary: str
    analogy: str
    why_it_matters: str
    action_steps: List[str]
    suggested_pattern: str


class CodebaseAiSummary(BaseModel):
    repository_name: str
    health_grade: str  # A+, A, B, C, D, F
    grade_color: str  # emerald, blue, amber, crimson
    headline: str
    executive_summary: str
    simple_breakdown: str
    key_strengths: List[str]
    critical_risks: List[str]
    prioritized_actions: List[AiActionItem]


class NodeAiExplanation(BaseModel):
    node_id: str
    node_name: str
    node_type: str
    role_in_architecture: str
    plain_english_role: str
    diagnosis: str
    analogy: Optional[str] = None
    why_it_matters: str
    recommended_refactoring: str
    easy_fix_steps: List[str] = []
    suggested_pattern: str
    refactoring_diff: Optional[str] = None


class AiCopilotEngine:
    """
    AI Architectural Copilot designed for humans and developers of all skill levels.
    Translates complex graph algorithms, circular dependency chains, and code metrics
    into crystal-clear, jargon-free explanations with real-world analogies.
    """

    @classmethod
    def calculate_health_grade(cls, debt_score: float) -> tuple[str, str]:
        """Maps debt score (0-100) to an intuitive report-card letter grade."""
        if debt_score <= 15:
            return "A+", "emerald"
        elif debt_score <= 25:
            return "A", "emerald"
        elif debt_score <= 45:
            return "B", "blue"
        elif debt_score <= 65:
            return "C", "amber"
        elif debt_score <= 80:
            return "D", "crimson"
        else:
            return "F", "crimson"

    @classmethod
    def generate_summary(
        cls,
        graph: CodebaseGraph,
        antipatterns: List[AntiPatternReport],
        debt_summary: ArchitecturalDebtSummary,
        refactoring_plans: List[RefactoringPlan],
    ) -> CodebaseAiSummary:
        """
        Generates an easy-to-understand codebase health review suitable for anyone.
        """
        grade, color = cls.calculate_health_grade(debt_summary.debt_score)
        total_modules = len(graph.modules)
        cycles = [ap for ap in antipatterns if ap.type == "CIRCULAR_DEPENDENCY"]
        god_classes = [ap for ap in antipatterns if ap.type == "GOD_CLASS"]
        hubs = [ap for ap in antipatterns if ap.type == "TIGHT_COUPLING"]

        # 1. Headline: Friendly, clear, direct
        if debt_summary.debt_score > 65:
            headline = f"Needs Cleanup: {len(antipatterns)} architectural tangles detected across {total_modules} files."
        elif debt_summary.debt_score > 35:
            headline = f"Good Foundation with a few cluttered spots across {total_modules} files."
        else:
            headline = f"Great Shape! Clean structure, easy to read, and well-organized."

        # 2. Key strengths (in plain English)
        strengths = []
        if not cycles:
            strengths.append("No import loops: Files do not depend on each other in circles, which makes testing fast and straightforward.")
        else:
            strengths.append(f"{total_modules - len(cycles)} files are cleanly isolated and run independently.")

        if debt_summary.average_maintainability_index >= 65:
            strengths.append(f"Clean readability: Code health score is {debt_summary.average_maintainability_index:.0f}/100, meaning functions are relatively easy to read and understand.")
        elif debt_summary.average_maintainability_index >= 45:
            strengths.append(f"Moderate readability: Most functions are reasonable in length, with a few complex spots.")

        if len(god_classes) == 0:
            strengths.append("Well-distributed duties: No single class is trying to do everything by itself.")

        package_count = len([n for n in graph.nodes if n.label == "Package"])
        if package_count > 1:
            strengths.append(f"Organized into {package_count} clear folders so it is easy to find where features live.")

        if not strengths:
            strengths.append("Base project structure is set up with standard module boundaries.")

        # 3. Critical risks (plain English: what could go wrong)
        risks = []
        if cycles:
            risks.append(f"{len(cycles)} tangled dependency loop(s): Two or more files import each other in a circle, which can cause subtle crashes when starting the app or writing unit tests.")
        if god_classes:
            risks.append(f"{len(god_classes)} overloaded class(es): These files do too many unrelated jobs at once. Editing one feature might accidentally break another.")
        if hubs:
            risks.append(f"{len(hubs)} bottleneck file(s): Too many other files rely directly on these. If you change a function here, you might have to fix 10 other files.")
        if debt_summary.average_complexity > 15:
            risks.append("Complicated logic: Several functions have many nested if-conditions, making them prone to edge-case bugs.")
        if not risks:
            risks.append("No critical architectural risks found — code is in healthy condition!")

        # 4. Simple Breakdown for beginners (no asterisks)
        simple_breakdown = (
            f"Think of this project as a team of {total_modules} files working together. "
            f"Currently, the overall team coordination score is {100 - debt_summary.debt_score:.0f}/100 (Grade {grade}). "
        )
        if cycles or god_classes or hubs:
            simple_breakdown += (
                f"The main roadblocks are: "
                f"{f'{len(cycles)} tangled loops where files get stuck waiting on each other' if cycles else ''}"
                f"{', ' if cycles and god_classes else ''}"
                f"{f'{len(god_classes)} overloaded classes doing too many jobs' if god_classes else ''}"
                f"{', and ' if (cycles or god_classes) and hubs else ''}"
                f"{f'{len(hubs)} bottleneck files causing traffic jams' if hubs else ''}. "
                f"Fixing these will make the app faster to build, easier to test, and much safer to update."
            )
        else:
            simple_breakdown += "The team is working smoothly with clear boundaries and minimal confusion."

        # 5. Executive Summary Narrative (no asterisks)
        top_hotspots = [
            h.get("name", "") if isinstance(h, dict) else getattr(h, "name", "")
            for h in debt_summary.critical_hotspots[:3]
        ]
        top_hotspots = [h for h in top_hotspots if h]
        hotspot_text = f" The files that need the most attention are {', '.join(top_hotspots)}." if top_hotspots else ""

        narrative = (
            f"{graph.repository_name} has {total_modules} files and {len(graph.nodes)} components "
            f"connected by {len(graph.edges)} dependencies. "
            f"Overall health is rated Grade {grade} with an Architectural Debt Score of {debt_summary.debt_score:.1f}/100.{hotspot_text} "
            f"Following the simple action checklist below will systematically resolve the biggest risks first."
        )

        # 6. Prioritized Action Items (clean, real, educational, no emojis)
        actions: List[AiActionItem] = []

        # Cycles
        for i, cycle in enumerate(cycles):
            cycle_mods = cycle.metrics.get("module_names", [])
            names_str = " <-> ".join(cycle_mods) if cycle_mods else cycle.entity_name
            actions.append(
                AiActionItem(
                    id=f"act-cycle-{i}",
                    title=f"Untangle Import Loop: {names_str}",
                    target_id=cycle.entity_id,
                    target_name=cycle.entity_name,
                    severity="CRITICAL",
                    difficulty="Easy (15 mins)",
                    debt_reduction_pct=15,
                    plain_english_summary="Two or more files import each other in a circle, like two people waiting on each other to speak first.",
                    analogy="Locked Room: File A needs a key inside File B, but File B's door needs the key inside File A. Neither can open cleanly.",
                    why_it_matters="Can cause mysterious 'cannot import name' startup crashes, slows down build tools, and prevents testing either file in isolation.",
                    action_steps=[
                        "Create a small third file called `types.py` or `models.py` for the shared data structures.",
                        "Move the shared classes/variables into that new file.",
                        "Update both files to import from the new shared file instead of importing each other.",
                    ],
                    suggested_pattern="Shared Types / Dependency Inversion",
                )
            )

        # God Classes
        for i, gc in enumerate(god_classes[:3]):
            wmc = gc.metrics.get("wmc", 0)
            loc = gc.metrics.get("loc", 0)
            actions.append(
                AiActionItem(
                    id=f"act-god-{i}",
                    title=f"Split Overloaded Class: '{gc.entity_name}'",
                    target_id=gc.entity_id,
                    target_name=gc.entity_name,
                    severity="HIGH",
                    difficulty="Medium (45 mins)",
                    debt_reduction_pct=12,
                    plain_english_summary=f"'{gc.entity_name}' has grown too large ({loc} lines, {wmc} decision paths) and is handling too many different responsibilities.",
                    analogy="Swiss Army Knife: Like a single tool that tries to be a knife, blender, hammer, and radio all in one. Hard to hold and breaks easily.",
                    why_it_matters="When one file handles everything, even small bug fixes or feature additions risk breaking unrelated parts of the app.",
                    action_steps=[
                        f"Look at '{gc.entity_name}' and group its methods by what they do (e.g. database work vs validation vs business rules).",
                        "Extract one group into its own helper class (e.g. create a dedicated service or repository).",
                        f"Have '{gc.entity_name}' call that helper instead of doing the work itself.",
                    ],
                    suggested_pattern="Single Responsibility Principle (Extract Helper Class)",
                )
            )

        # Coupling Hubs
        for i, hub in enumerate(hubs[:2]):
            fan_in = hub.metrics.get("fan_in", 0)
            fan_out = hub.metrics.get("fan_out", 0)
            actions.append(
                AiActionItem(
                    id=f"act-hub-{i}",
                    title=f"Reduce Traffic Jam on '{hub.entity_name}'",
                    target_id=hub.entity_id,
                    target_name=hub.entity_name,
                    severity="MEDIUM",
                    difficulty="Medium (30 mins)",
                    debt_reduction_pct=8,
                    plain_english_summary=f"Too many parts of the app ({fan_in} callers) rely directly on '{hub.entity_name}', which also reaches out to {fan_out} other files.",
                    analogy="Roundabout Bottleneck: When every road in town is forced through one single roundabout, any fender-bender causes gridlock everywhere.",
                    why_it_matters="If you ever rename a function or change a parameter here, you will have to manually update and re-test dozens of files.",
                    action_steps=[
                        "Group the functions in this file into distinct sub-modules by purpose.",
                        "Provide a clean, simple interface (Facade) so callers only see what they actually need.",
                    ],
                    suggested_pattern="Facade Pattern",
                )
            )

        # Gemini live enhancement (if API key available)
        gemini_key = os.environ.get("GEMINI_API_KEY")
        if gemini_key:
            try:
                from google import genai
                client = genai.Client(api_key=gemini_key)
                prompt = (
                    f"You are a friendly, encouraging senior software architect reviewing a codebase for a beginner-to-intermediate developer.\n"
                    f"Repository: {graph.repository_name}\n"
                    f"Files: {total_modules}, Entities: {len(graph.nodes)}\n"
                    f"Debt Score: {debt_summary.debt_score:.1f}/100 (Grade {grade})\n"
                    f"Issues: {len(cycles)} circular imports, {len(god_classes)} overloaded classes, {len(hubs)} bottleneck files.\n"
                    f"Top Hotspots: {', '.join(top_hotspots)}\n\n"
                    f"Write a 2-paragraph summary in warm, approachable, everyday language without markdown asterisks (**), jargon, or emojis:\n"
                    f"Paragraph 1: Praise what is working well, explain the overall health grade honestly without scary jargon, and use a simple real-world analogy.\n"
                    f"Paragraph 2: Explain the single most important thing to fix first, why it matters, and how it will immediately help."
                )
                response = client.models.generate_content(
                    model="gemini-2.5-flash",
                    contents=prompt,
                )
                if response and response.text:
                    # Strip any markdown bold asterisks if the model still generated them
                    narrative = response.text.replace("**", "").strip()
            except Exception:
                pass

        return CodebaseAiSummary(
            repository_name=graph.repository_name,
            health_grade=grade,
            grade_color=color,
            headline=headline,
            executive_summary=narrative,
            simple_breakdown=simple_breakdown,
            key_strengths=strengths,
            critical_risks=risks,
            prioritized_actions=actions,
        )

    @classmethod
    def explain_node(
        cls,
        node_id: str,
        graph: CodebaseGraph,
        antipatterns: List[AntiPatternReport],
        refactoring_plans: List[RefactoringPlan],
    ) -> NodeAiExplanation:
        """
        Explains an individual file or component in crystal-clear, plain English
        with analogies and realistic before-and-after guidance.
        """
        target_node: Optional[GraphNode] = None
        for n in graph.nodes:
            if n.id == node_id:
                target_node = n
                break

        node_name = target_node.name if target_node else node_id.split("::")[-1]
        node_type = target_node.label.lower() if target_node else "module"
        node_props = target_node.properties if target_node else {}

        matching_smells = [
            ap for ap in antipatterns
            if ap.entity_id == node_id or ap.entity_name == node_name
            or (ap.type == "CIRCULAR_DEPENDENCY" and node_id in ap.metrics.get("cycle_path", []))
        ]

        matching_plan = next(
            (p for p in refactoring_plans if p.target_id == node_id or p.target_name == node_name),
            None
        )

        cc = node_props.get("cyclomatic_complexity", 1)
        loc = node_props.get("loc", 0)
        mi = node_props.get("maintainability_index", 100)

        # Plain-English Role
        if node_type == "package":
            plain_role = f"A folder that groups related files together."
            role = f"Folder package grouping {node_props.get('module_count', 1)} related source files."
        elif node_type == "module":
            plain_role = f"A single code file containing logic for '{node_name}'."
            role = f"Source module defining functions and data for {node_props.get('file_path', node_name)}."
        elif node_type == "class":
            plain_role = f"A blueprint defining state and actions ({len(node_props.get('methods', []))} methods)."
            role = f"Class structure defining object properties and behaviors."
        elif node_type == "edge":
            plain_role = "Edge CDN & Security layer handling global traffic routing and encryption."
            role = f"Edge network component: {node_props.get('category', 'CDN/WAF')}."
        elif node_type == "gateway":
            plain_role = "Ingress reverse proxy directing traffic to appropriate backend applications."
            role = f"Network gateway: {node_props.get('server', node_name)}."
        elif node_type == "service":
            plain_role = f"Core application service executing business logic and serving users."
            role = f"Application tier component ({node_props.get('framework', node_props.get('runtime', node_name))})."
        elif node_type == "database":
            plain_role = f"Storage/cache engine maintaining persistent state or cache data."
            role = f"Data storage service running on port {node_props.get('port', 'unknown')}."
        elif node_type == "thirdparty":
            plain_role = f"External cloud API or third-party SaaS integration."
            role = f"Third-party integration: {node_name}."
        elif node_type == "infrastructure":
            plain_role = f"Core domain infrastructure managing DNS records and nameserver resolution."
            role = f"Infrastructure layer: {node_name}."
        else:
            plain_role = f"A specific function that performs a single task."
            role = f"Executable function handling logic calculation."

        # Diagnosis, analogy, and fix (no asterisks, no emojis)
        analogy = None
        easy_steps = []

        if matching_smells:
            first_smell = matching_smells[0]
            has_cycle = any(s.type == "CIRCULAR_DEPENDENCY" for s in matching_smells)
            has_god = any(s.type == "GOD_CLASS" for s in matching_smells)
            has_coupling = any(s.type == "TIGHT_COUPLING" for s in matching_smells)
            has_exposed_db = any(s.type == "EXPOSED_DATABASE_PORT" for s in matching_smells)
            has_sec_headers = any(s.type == "MISSING_SECURITY_HEADERS" for s in matching_smells)
            has_tls_smell = any(s.type == "INSECURE_OR_EXPIRING_TLS" for s in matching_smells)
            has_email_smell = any(s.type == "EMAIL_SPOOFING_VULNERABILITY" for s in matching_smells)

            if has_exposed_db:
                diagnosis = f"Port is publicly reachable across the Internet without firewall isolation."
                analogy = "Leaving the vault door wide open onto the sidewalk instead of inside a secure backroom."
                why_matters = "Allows automated port scanners and brute-force tools to attack data directly."
                recom = "Apply firewall rules (AWS Security Group / UFW) to bind service strictly to private IP or localhost."
                pattern = "Network Boundary Isolation"
                easy_steps = [
                    "Block the database port from 0.0.0.0/0 in your firewall.",
                    "Configure backend application to connect via private VPC subnet or localhost.",
                ]
            elif has_sec_headers:
                diagnosis = f"HTTP reverse proxy is missing defense-in-depth security response headers."
                analogy = "A store with security cameras installed outside but no locks on the display cases."
                why_matters = "Leaves visitors vulnerable to clickjacking, unauthorized script execution, and MIME confusion."
                recom = "Add HSTS, CSP, X-Frame-Options, and X-Content-Type-Options headers in your reverse proxy config."
                pattern = "HTTP Defense-in-Depth Hardening"
                easy_steps = [
                    "Enable Strict-Transport-Security (HSTS) with a max-age of 31536000 seconds.",
                    "Add X-Frame-Options: DENY and X-Content-Type-Options: nosniff headers.",
                ]
            elif has_tls_smell:
                diagnosis = f"SSL/TLS certificate is expiring soon or expired, threatening service uptime."
                analogy = "An expiring passport right before an international flight."
                why_matters = "Browsers display aggressive warning screens, blocking 99% of visitors from accessing the site."
                recom = "Renew certificate immediately and configure automated renewal via certbot or cloud ACME."
                pattern = "Automated Certificate Lifecycle"
                easy_steps = [
                    "Trigger manual certificate renewal command.",
                    "Verify cron or systemd timer is enabled for automated background renewal.",
                ]
            elif has_email_smell:
                diagnosis = f"DNS is missing SPF or DMARC authentication records for this domain."
                analogy = "Mailing letters without a return address verification seal - anyone can forge your letterhead."
                why_matters = "Phishers and scammers can send fraudulent emails pretending to be your company."
                recom = "Publish valid SPF TXT record and DMARC TXT record in your DNS zone."
                pattern = "Email Authentication (SPF/DMARC)"
                easy_steps = [
                    "Add TXT record for domain with 'v=spf1 mx ~all'.",
                    "Add TXT record for _dmarc with 'v=DMARC1; p=reject;'.",
                ]
            elif has_cycle:
                diagnosis = f"This file is caught in a circular import loop. It imports another file that directly or indirectly imports it right back."
                analogy = "Chicken and Egg: Neither file can fully start up without the other already being loaded."
                why_matters = "Can cause random 'cannot import name' crashes during startup, breaks unit testing, and makes build tools slow."
                recom = "Extract whatever both files share (like data classes, types, or helper functions) into a separate, independent file."
                pattern = "Shared Kernel / Dependency Inversion"
                easy_steps = [
                    "Identify the specific variable or class that both files need.",
                    "Move that variable or class into a new file (e.g. shared_types.py).",
                    "In both files, replace the direct import with an import from shared_types.py.",
                ]
            elif has_god:
                diagnosis = f"This class is doing too many different things ({loc} lines, {cc} decision branches)."
                analogy = "Overstuffed Backpack: When you pack everything into one bag, finding one item is slow, and adjusting a strap might tear a zipper."
                why_matters = "Whenever you touch this class, you risk accidentally breaking one of its other responsibilities."
                recom = "Split this large class into smaller helper classes that each handle one specific job."
                pattern = "Single Responsibility (Extract Class)"
                easy_steps = [
                    "List the 2-3 main jobs this class performs (e.g. data fetching vs formatting vs validation).",
                    "Create a new helper class for one of those jobs.",
                    "Delegate that job to the helper class instead of keeping all the code inside this one class.",
                ]
            else:
                diagnosis = f"{first_smell.description}"
                analogy = "Overloaded Power Strip: Too many appliances plugged into one socket."
                why_matters = first_smell.refactoring_suggestion
                recom = first_smell.refactoring_suggestion
                pattern = "Architectural Refactoring"
                easy_steps = [
                    "Review component connections in the architecture graph.",
                    "Decouple dependencies and apply defensive configurations.",
                ]
        elif cc > 15:
            diagnosis = f"This code works, but has deeply nested logic ({cc} decision paths in {loc} lines)."
            analogy = "Dense Maze: With so many twists and turns, it is easy for a bug to hide in an untested branch."
            why_matters = "Harder for team members to read, and difficult to test every possible combination of conditions."
            recom = "Break nested if-statements into small helper functions with clear names."
            pattern = "Early Return / Guard Clauses"
            easy_steps = [
                "Use 'early returns' (guard clauses) to exit functions early when inputs are invalid.",
                "Extract complex condition checks into descriptive boolean helper functions.",
            ]
        else:
            diagnosis = f"Looking healthy! Complexity is low ({cc}) and maintainability is solid ({mi:.0f}/100)."
            analogy = "Neat Desk: Everything is in its place, making it easy to find and work with."
            why_matters = "This file is easy to read, test, and safely modify without surprises."
            recom = "Keep up the clean structure and ensure you have unit tests in place."
            pattern = "Clean Code Standard"
            easy_steps = [
                "Add or maintain automated unit tests for this component.",
                "Keep functions under 30 lines when possible.",
            ]

        # Use matching refactoring plan diff if available
        diff_preview = matching_plan.code_diff_preview if matching_plan else None

        # Gemini live enhancement (if available)
        gemini_key = os.environ.get("GEMINI_API_KEY")
        if gemini_key:
            try:
                from google import genai
                client = genai.Client(api_key=gemini_key)
                prompt = (
                    f"Explain this code file to a developer who is new to software architecture:\n"
                    f"File: {node_name} ({node_type})\n"
                    f"Lines of Code: {loc}, Complexity: {cc}, Maintainability: {mi:.0f}/100\n"
                    f"Issues: {[s.type for s in matching_smells]}\n"
                    f"In 2 simple sentences without jargon, emojis, or markdown asterisks (**), explain: 1) What is the main issue or status? 2) What is the easiest way to improve it?"
                )
                res = client.models.generate_content(model="gemini-2.5-flash", contents=prompt)
                if res and res.text:
                    diagnosis = res.text.replace("**", "").strip()
            except Exception:
                pass

        return NodeAiExplanation(
            node_id=node_id,
            node_name=node_name,
            node_type=node_type,
            role_in_architecture=role,
            plain_english_role=plain_role,
            diagnosis=diagnosis,
            analogy=analogy,
            why_it_matters=why_matters,
            recommended_refactoring=recom,
            easy_fix_steps=easy_steps,
            suggested_pattern=matching_plan.pattern if matching_plan else pattern,
            refactoring_diff=diff_preview,
        )
