/** Opt-in Hermes Desktop 0.17.0 companion. It is never a security boundary. */
import { HermesPlugin } from "@hermes/plugin-sdk";

export default class HermesKanbanWorkflowPlugin extends HermesPlugin {
  async activate(ctx) {
    ctx.register("hermes-kanban-workflow.status", async () =>
      ctx.rest.get("/api/plugins/hermes-kanban-workflow/status")
    );
  }
}

