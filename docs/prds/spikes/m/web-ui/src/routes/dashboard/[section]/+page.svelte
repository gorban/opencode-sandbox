<script lang="ts">
  import { goto } from '$app/navigation';
  import { flushSync, onMount } from 'svelte';
  import type { Project, Sandbox, Thread } from '#lib/projection.ts';
  import { browserTransport } from '#lib/transport.ts';
  import { Workspace } from '#lib/workspace.ts';
  import type { View } from '#lib/workspace.ts';

  let { data }: { data: { section: string } } = $props();

  const sections = ['Projects', 'Sandboxes', 'Threads'];
  let sectionTitle = $derived(sections.find((section) => section.toLowerCase() === data.section));
  let view: View = $state.raw({
    phase: 'checking', snapshot: null, message: 'Checking session',
    authBusy: false, authBlocked: false, canLogout: false
  });
  let selection = $state.raw<{ project?: string; sandbox?: string; thread?: string }>({});
  let selectedProject = $derived(
    view.snapshot?.projects.find(({ id }) => id === selection.project) ?? view.snapshot?.projects[0]
  );
  let selectedSandbox = $derived(
    selectedProject?.sandboxes.find(({ id }) => id === selection.sandbox) ?? selectedProject?.sandboxes[0]
  );
  let selectedThread = $derived(
    selectedSandbox?.threads.find(({ id }) => id === selection.thread) ?? selectedSandbox?.threads[0]
  );
  let heading = $state<HTMLHeadingElement>();
  let code = $state('');
  const workspace = new Workspace(browserTransport(), (next) => {
    if (next.phase === 'signed-out' && view.snapshot) {
      flushSync(() => {
        view = next;
        selection = {};
      });
      return;
    }
    view = next;
    if (next.phase === 'checking' || next.phase === 'signed-out') selection = {};
    if (next.snapshot) {
      const projects = next.snapshot.projects;
      const project = projects.find(({ id }) => id === selection.project) ?? projects[0];
      const sandbox = project?.sandboxes.find(({ id }) => id === selection.sandbox) ?? project?.sandboxes[0];
      const thread = sandbox?.threads.find(({ id }) => id === selection.thread) ?? sandbox?.threads[0];
      selection = { project: project?.id, sandbox: sandbox?.id, thread: thread?.id };
    }
  });

  $effect(() => {
    if (data.section === 'sandboxes' && selectedSandbox &&
        !performance.getEntriesByName('first-populated-sandbox-list').length) {
      performance.mark('first-populated-sandbox-list');
    }
  });

  onMount(() => {
    function pause() {
      flushSync(() => {
        code = '';
        workspace.suspend();
      });
    }

    function restore() {
      if (document.visibilityState !== 'visible') return;
      pause();
      void workspace.resume();
    }

    function onVisibility() {
      if (document.visibilityState === 'visible') restore();
      else pause();
    }

    function onPageShow(event: PageTransitionEvent) {
      if (event.persisted) onVisibility();
    }

    window.addEventListener('pagehide', pause);
    window.addEventListener('pageshow', onPageShow);
    document.addEventListener('visibilitychange', onVisibility);
    onVisibility();
    return () => {
      window.removeEventListener('pagehide', pause);
      window.removeEventListener('pageshow', onPageShow);
      document.removeEventListener('visibilitychange', onVisibility);
      pause();
    };
  });

  async function move(section: string) {
    await goto('/dashboard/' + section);
    heading?.focus();
  }

  function chooseProject(project: Project) {
    selection = { project: project.id };
    void move('sandboxes');
  }

  function chooseSandbox(sandbox: Sandbox) {
    selection = { project: selectedProject?.id, sandbox: sandbox.id };
    void move('threads');
  }

  function chooseThread(thread: Thread) {
    selection = { project: selectedProject?.id, sandbox: selectedSandbox?.id, thread: thread.id };
    heading?.focus();
  }

  function signIn() {
    const input = code;
    code = '';
    if (input) void workspace.exchange(input);
  }
</script>

<svelte:head>
  <title>{sectionTitle} · Workspace dashboard</title>
</svelte:head>

<div class="shell" data-sveltekit-preload-code="false" data-sveltekit-preload-data="false">
  <header>
    <a class="brand" href="/dashboard/projects">Workspace</a>
    {#if view.canLogout}
      <div class="actions">
        <button type="button" onclick={() => workspace.refresh()}>Refresh</button>
        <button type="button" onclick={() => workspace.logout()}>Sign out</button>
      </div>
    {/if}
  </header>

  <main>
    <p class="status" role="status">{view.message}</p>
    {#if view.phase === 'signed-out' && !view.authBlocked}
      <section class="sign-in" aria-labelledby="signin-heading">
        <h1 id="signin-heading">Open the dashboard</h1>
        <label for="bootstrap">One-use code</label>
        <input
          id="bootstrap"
          type="password"
          maxlength="256"
          autocomplete="off"
          spellcheck="false"
          bind:value={code}
          disabled={view.authBusy}
          onkeydown={(event) => {
            if (event.key === 'Enter') {
              event.preventDefault();
              signIn();
            }
          }}
        >
        <button type="button" onclick={signIn} disabled={view.authBusy || !code}>Sign in</button>
      </section>
    {:else if view.phase === 'error'}
      <h1>Workspace</h1>
      <button type="button" onclick={() => workspace.refresh()}>Retry</button>
    {:else if view.snapshot}
      <nav aria-label="Workspace views">
        {#each sections as section (section)}
          {@const path = section.toLowerCase()}
          <a href={'/dashboard/' + path} aria-current={data.section === path ? 'page' : undefined}>
            {section}
          </a>
        {/each}
      </nav>
      {#if data.section === 'projects'}
        <h1 tabindex="-1" bind:this={heading}>Projects</h1>
        {#if !selectedProject}<p>No projects available.</p>{/if}
        <ul class="picker">
          {#each view.snapshot.projects as project (project.id)}
            <li><button type="button" onclick={() => chooseProject(project)}>
              <bdi>{project.label}</bdi><span>{project.sandboxes.length} sandboxes</span>
            </button></li>
          {/each}
        </ul>
      {:else if data.section === 'sandboxes'}
        <h1 tabindex="-1" bind:this={heading}>Sandboxes</h1>
        {#if selectedProject}<p class="context"><bdi>{selectedProject.label}</bdi></p>{/if}
        {#if !selectedSandbox}<p>No sandboxes available.</p>{/if}
        <ul class="picker" data-sandbox-list={selectedSandbox ? '' : undefined}>
          {#each selectedProject?.sandboxes ?? [] as sandbox (sandbox.id)}
            <li><button type="button" onclick={() => chooseSandbox(sandbox)}>
              <bdi>{sandbox.label}</bdi><span>{sandbox.status}</span>
            </button></li>
          {/each}
        </ul>
      {:else}
        <h1 tabindex="-1" bind:this={heading}>Threads</h1>
        {#if selectedSandbox}
          <p class="context"><bdi>{selectedSandbox.label}</bdi><span> · {selectedSandbox.status}</span></p>
        {/if}
        {#if !selectedThread}<p>No threads available.</p>{/if}
        <div class="thread-layout">
          <ul class="picker" aria-label="Threads">
            {#each selectedSandbox?.threads ?? [] as thread (thread.id)}
              <li><button
                type="button"
                aria-pressed={thread.id === selectedThread?.id}
                onclick={() => chooseThread(thread)}
              ><bdi>{thread.label}</bdi></button></li>
            {/each}
          </ul>
          {#if selectedThread}
            <article>
              <h2><bdi>{selectedThread.label}</bdi></h2>
              <section aria-labelledby="mailbox-heading">
                <h3 id="mailbox-heading">Mailbox</h3>
                {#if !selectedThread.mailbox.length}<p>No messages.</p>{/if}
                <ul>
                  {#each selectedThread.mailbox as row}
                    <li class="body"><bdi>{row.text}</bdi></li>
                  {/each}
                </ul>
              </section>
              {#each [{ name: 'provenance', entries: selectedThread.provenance }, { name: 'events', entries: selectedThread.events }] as group (group.name)}
                <section aria-labelledby={group.name + '-heading'}>
                  <h3 id={group.name + '-heading'}>{group.name === 'events' ? 'Events' : 'Provenance'}</h3>
                  {#if !group.entries.length}<p>No entries.</p>{/if}
                  <ul>
                    {#each group.entries as row}
                      <li><strong><bdi>{row.label}</bdi></strong><div class="body"><bdi>{row.text}</bdi></div></li>
                    {/each}
                  </ul>
                </section>
              {/each}
            </article>
          {/if}
        </div>
      {/if}
    {/if}
  </main>
</div>

<style>
  :global(html) { color: #1d2b2b; background: #f3f4ef; font-family: system-ui, sans-serif; }
  :global(body) { margin: 0; }
  :global(:focus-visible) { outline: 3px solid #176a67; outline-offset: 4px; }
  .shell { max-width: 64rem; margin: auto; padding: 0 1.25rem 3rem; }
  header { min-height: 4.5rem; border-bottom: 1px solid #c8d2cd; display: flex; align-items: center; justify-content: space-between; gap: 1rem; flex-wrap: wrap; }
  .brand { color: inherit; font-size: 1.3rem; font-weight: 750; }
  main { padding-top: 1.25rem; }
  nav, .actions { display: flex; flex-wrap: wrap; gap: .75rem; }
  nav a { color: #28504d; padding: .5rem 0; }
  nav a[aria-current] { font-weight: 750; text-decoration-thickness: .15em; }
  h1 { font-size: clamp(1.7rem, 5vw, 2.5rem); margin: 1rem 0; }
  h2 { margin-top: 0; }
  .context, .status, .picker button span { color: #405956; }
  .status { min-height: 1.4em; }
  button, input { box-sizing: border-box; font: inherit; color: inherit; border: 1px solid #788e87; border-radius: .4rem; background: #fcfdfa; padding: .65rem .8rem; }
  button { cursor: pointer; }
  button:disabled { cursor: default; opacity: .7; }
  button:hover:not(:disabled), button[aria-pressed="true"] { background: #e1eeea; }
  .sign-in { margin-top: 1rem; }
  .sign-in label { display: block; margin-bottom: .45rem; }
  .sign-in input { margin-right: .5rem; max-width: 100%; }
  ul { list-style: none; margin: 0; padding: 0; }
  .picker { display: grid; gap: .6rem; align-content: start; }
  .picker button { display: flex; justify-content: space-between; gap: .75rem; width: 100%; text-align: start; }
  .picker button bdi, .body, .context { overflow-wrap: anywhere; min-width: 0; }
  .thread-layout { display: grid; grid-template-columns: minmax(8rem, 1fr) minmax(0, 3fr); align-items: start; gap: 1rem; }
  article { background: #fcfdfa; border: 1px solid #c8d2cd; border-radius: .5rem; min-width: 0; padding: 1rem; overflow-wrap: anywhere; }
  article li { border-top: 1px solid #d7e1dc; padding: .65rem 0; }
  .body { white-space: pre-wrap; }
  @media (max-width: 36rem) { .thread-layout { grid-template-columns: 1fr; } }
</style>
