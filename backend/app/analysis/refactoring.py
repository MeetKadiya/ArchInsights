from typing import List
from pydantic import BaseModel, Field
from app.analysis.anti_patterns import AntiPatternReport


class RefactoringPlan(BaseModel):
    id: str
    target_id: str
    target_name: str
    title: str
    pattern: str  # E.g. Dependency Inversion, Extract Class, Mediator
    debt_reduction_pct: int
    steps: List[str]
    code_diff_preview: str


class RefactoringGenerator:
    """
    Generates actionable, automated refactoring suggestions and architectural
    redesign blueprints based on detected anti-patterns.
    """

    @classmethod
    def generate_plans(cls, reports: List[AntiPatternReport]) -> List[RefactoringPlan]:
        plans: List[RefactoringPlan] = []

        for report in reports:
            if report.type == "CIRCULAR_DEPENDENCY":
                plans.append(cls._plan_for_circular_dependency(report))
            elif report.type == "GOD_CLASS":
                plans.append(cls._plan_for_god_class(report))
            elif report.type == "TIGHT_COUPLING":
                plans.append(cls._plan_for_tight_coupling(report))
            elif report.type == "SHOTGUN_SURGERY":
                plans.append(cls._plan_for_shotgun_surgery(report))
            elif report.type == "ORPHAN_MODULE":
                plans.append(cls._plan_for_orphan_module(report))

        return plans

    @classmethod
    def _plan_for_circular_dependency(cls, report: AntiPatternReport) -> RefactoringPlan:
        cycle_names = report.metrics.get("module_names", ["ModuleA", "ModuleB"])
        mod_a = cycle_names[0] if len(cycle_names) > 0 else "ModuleA"
        mod_b = cycle_names[1] if len(cycle_names) > 1 else "ModuleB"

        diff = f"""// --- BEFORE: Circular import cycle between {mod_a} and {mod_b} ---
// In {mod_a}:
import {{ {mod_b}Helper }} from './{mod_b}';
export function runA() {{ {mod_b}Helper(); }}

// In {mod_b}:
import {{ runA }} from './{mod_a}';
export function {mod_b}Helper() {{ runA(); }}

// --- AFTER: Decouple using Shared Kernel / Dependency Inversion ---
// Create 'types.ts' / 'interfaces.py':
export interface ISharedContract {{
    execute(): void;
}}

// Inject dependency or use event emitter:
export function runA(helper: ISharedContract) {{
    helper.execute();
}}
"""
        return RefactoringPlan(
            id=f"plan_cycle_{report.entity_id}",
            target_id=report.entity_id,
            target_name=report.entity_name,
            title=f"Break Circular Import Cycle in {report.entity_name}",
            pattern="Dependency Inversion Principle (DIP) & Shared Interface",
            debt_reduction_pct=35,
            steps=[
                f"1. Create a leaf module '{mod_a.split('.')[0]}_contracts' or 'shared/types'.",
                "2. Extract shared type definitions, data models, or callback interfaces into the leaf module.",
                f"3. Invert the dependency: Pass instances or callbacks into {mod_a} rather than direct hardcoded imports.",
                f"4. Remove circular import statements from {mod_a} and {mod_b}.",
                "5. Verify acyclic dependency graph with automated tests.",
            ],
            code_diff_preview=diff,
        )

    @classmethod
    def _plan_for_god_class(cls, report: AntiPatternReport) -> RefactoringPlan:
        wmc = report.metrics.get("wmc", 0)
        loc = report.metrics.get("loc", 0)

        diff = f"""// --- BEFORE: God Class '{report.entity_name}' (LOC: {loc}, WMC: {wmc}) ---
class {report.entity_name}:
    def authenticate_user(self): ...
    def process_payment(self): ...
    def generate_pdf_invoice(self): ...
    def send_notification_email(self): ...

// --- AFTER: Decomposed into Cohesive Single-Responsibility Services ---
class AuthService:
    def authenticate_user(self): ...

class PaymentService:
    def process_payment(self): ...

class InvoiceService:
    def generate_pdf(self): ...

// Facade coordinates domain interactions without bloating
class {report.entity_name}Facade:
    def __init__(self, auth: AuthService, payment: PaymentService, invoice: InvoiceService):
        self.auth = auth
        self.payment = payment
        self.invoice = invoice
"""
        return RefactoringPlan(
            id=f"plan_god_{report.entity_id}",
            target_id=report.entity_id,
            target_name=report.entity_name,
            title=f"Decompose God Class '{report.entity_name}'",
            pattern="Single Responsibility Principle (SRP) & Facade Pattern",
            debt_reduction_pct=45,
            steps=[
                f"1. Audit all methods of {report.entity_name} and cluster them into domain boundaries (e.g. Auth, Processing, Reporting).",
                "2. Extract dedicated smaller service classes for each cluster.",
                f"3. Retain {report.entity_name} as a lightweight Facade delegating to the new specialized services to preserve backward compatibility.",
                "4. Update callers progressively to use focused interfaces.",
            ],
            code_diff_preview=diff,
        )

    @classmethod
    def _plan_for_tight_coupling(cls, report: AntiPatternReport) -> RefactoringPlan:
        fi = report.metrics.get("fan_in", 0)
        fo = report.metrics.get("fan_out", 0)

        diff = f"""// --- BEFORE: Tight Coupling Hub '{report.entity_name}' (Fan-In: {fi}, Fan-Out: {fo}) ---
// Direct coupling to 6+ disparate modules

// --- AFTER: Event Bus / Mediator Decoupling ---
class EventBus:
    def publish(self, topic: str, payload: dict): ...
    def subscribe(self, topic: str, handler: callable): ...

// Modules react asynchronously rather than depending on concrete orchestrators
event_bus.publish('order.created', {{'order_id': 123}})
"""
        return RefactoringPlan(
            id=f"plan_coupling_{report.entity_id}",
            target_id=report.entity_id,
            target_name=report.entity_name,
            title=f"Decouple Hub Module '{report.entity_name}'",
            pattern="Mediator & Event-Driven Architecture",
            debt_reduction_pct=30,
            steps=[
                f"1. Identify the {fo} outgoing dependencies from '{report.entity_name}'.",
                "2. Replace direct method invocations with asynchronous events or publisher-subscriber channels.",
                "3. Introduce interface abstraction layers for incoming consumers.",
                "4. Measure reduction in Afferent/Efferent coupling.",
            ],
            code_diff_preview=diff,
        )

    @classmethod
    def _plan_for_shotgun_surgery(cls, report: AntiPatternReport) -> RefactoringPlan:
        fo = report.metrics.get("fan_out", 6)
        diff = f"""// --- BEFORE: High Fan-Out '{report.entity_name}' imports {fo} modules ---
// import {{ A }} from './a';
// import {{ B }} from './b';
// import {{ C }} from './c';
// ...

// --- AFTER: Aggregate through a Cohesive Facade ---
// import {{ UnifiedDomainFacade }} from './domain_facade';
// UnifiedDomainFacade.executeWorkflow();
"""
        return RefactoringPlan(
            id=f"plan_shotgun_{report.entity_id}",
            target_id=report.entity_id,
            target_name=report.entity_name,
            title=f"Consolidate Outbound Coupling in '{report.entity_name}'",
            pattern="Facade & Parameter Object",
            debt_reduction_pct=25,
            steps=[
                f"1. Audit the {fo} outgoing imports in '{report.entity_name}'.",
                "2. Group related operations into a high-level Domain Facade.",
                "3. Delegate workflow coordination to the Facade instead of direct multi-module imports.",
            ],
            code_diff_preview=diff,
        )

    @classmethod
    def _plan_for_orphan_module(cls, report: AntiPatternReport) -> RefactoringPlan:
        diff = f"""// --- AUDIT: Orphan module '{report.entity_name}' ---
// 0 incoming callers and 0 outgoing dependencies
// Option A: Wire module into application router/dependency container
// Option B: Archive / delete dead module if obsolete
"""
        return RefactoringPlan(
            id=f"plan_orphan_{report.entity_id}",
            target_id=report.entity_id,
            target_name=report.entity_name,
            title=f"Audit Orphan Module '{report.entity_name}'",
            pattern="Dead Code Elimination & Pruning",
            debt_reduction_pct=15,
            steps=[
                f"1. Verify if '{report.entity_name}' is invoked dynamically via reflection or plugins.",
                "2. If obsolete, remove file and clean up repo.",
                "3. If active, connect to consumer modules or export public API.",
            ],
            code_diff_preview=diff,
        )
