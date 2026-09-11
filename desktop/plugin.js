/** Opt-in Hermes Desktop 0.17.0 companion. It is never a security boundary. */

const ID = 'hermes-kanban-workflow'

export default {
  id: ID,
  name: 'Hermes Kanban Workflow',
  defaultEnabled: false,
  register(ctx) {
    ctx.register({
      id: 'status',
      area: 'statusBar.right',
      order: 80,
      data: {
        label: 'Kanban observe-only',
        onClick: async () => ctx.rest('/status', { method: 'GET' })
      }
    })
  }
}
