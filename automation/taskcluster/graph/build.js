var fs = require("fs");
var path = require("path");
var yaml = require("js-yaml");
var merge = require("merge");
var slugid = require("slugid");
var flatmap = require("flatmap");
var taskids = {};

// TODO
function taskid(id) {
  if (!(id in taskids)) {
    taskids[id] = slugid.v4();
  }
  return taskids[id];
}

// TODO
function from_now(hours) {
  var d = new Date();
  d.setHours(d.getHours() + (hours || 0));
  return d.toJSON();
}

// TODO
function build_task(id, def) {
  var task, retvals = [{
    taskId: taskid(id),
    task: task = {
      scopes: [
        "queue:route:tc-treeherder-stage.nss." + process.env.TC_REVISION,
        "queue:route:tc-treeherder.nss." + process.env.TC_REVISION,
        "scheduler:extend-task-graph:*"
      ],

      routes: [
        "tc-treeherder-stage.nss." + process.env.TC_REVISION_HASH,
        "tc-treeherder.nss." + process.env.TC_REVISION_HASH
      ],

      payload: {
        image: process.env.TC_DOCKER_IMAGE,
        maxRunTime: 3600
        /*features: {
          taskclusterProxy: true
        }*/
      },

      metadata: {
        owner: process.env.TC_OWNER,
        source: process.env.TC_SOURCE
      },

      extra: {
        treeherder: {
          revision: process.env.TC_REVISION,
          revision_hash: process.env.TC_REVISION_HASH
        }
      }
    }
  }];

  // Fill in some basic data.
  task.created = from_now(0);
  task.deadline = from_now(24);
  task.provisionerId = process.env.TC_PROVISIONER_ID || "aws-provisioner-v1";
  task.workerType = process.env.TC_WORKER_TYPE || "hg-worker";
  task.schedulerId = "task-graph-scheduler";

  // Clone definition.
  def = merge.recursive(true, {}, def);

  // Extend task definition.
  while (def.extends) {
    var base = def.extends;
    delete def.extends;

    var template = doc.templates[base];
    def = merge.recursive(true, template, def);
  }

  // Fill in attributes.
  task.metadata.name = def.name;
  task.metadata.description = def.description;
  task.payload.command = def.command;
  task.payload.env = def.env || {};
  task.extra.treeherder = merge.recursive(true, task.extra.treeherder, def.treeherder || {});

  // Forward some GitHub env variables.
  task.payload.env.NSS_HEAD_REPOSITORY = process.env.NSS_HEAD_REPOSITORY;
  task.payload.env.NSS_HEAD_REVISION = process.env.NSS_HEAD_REVISION;

  // Register artifacts.
  if (def.artifact) {
    task.payload.artifacts = {
      "public": {
        "type": "directory",
        "path": "/home/worker/artifacts",
        "expires": from_now(24)
      }
    };
  }

  // Create subtasks.
  if ("subtasks" in def) {
    def.subtasks.forEach(function (sid) {
      if (!(sid in doc.templates)) {
        throw new Error("Can't find template '" + sid + "'");
      }

      var subtasks = build_task(id + "_" + sid, doc.templates[sid]);

      // TODO
      subtasks.forEach(function (subtask) {
        subtask.task.payload.env = merge.recursive(true, task.payload.env, subtask.task.payload.env);
        subtask.task.extra.treeherder = merge.recursive(true, task.extra.treeherder, subtask.task.extra.treeherder);

        // TODO
        if (!subtask.task.metadata.description) {
          subtask.task.metadata.description = task.metadata.description;
        }

        // TODO
        if (!subtask.requires) {
          subtask.requires = [taskid(id)];
          subtask.task.payload.env.TC_PARENT_TASK_ID = taskid(id);
        }
      });

      // Append subtasks.
      retvals = retvals.concat(subtasks);
    });
  }

  return retvals;
}

// Load the tasks definition file.
var source = fs.readFileSync(path.join(__dirname, "./graph.yml"), "utf-8");
var doc = yaml.load(source);

// Build the graph.
var graph = {tasks: flatmap(Object.keys(doc.graph), function (id) {
  return build_task(id, doc.graph[id]);
})};

// Clean up env variables.
graph.tasks.forEach(function (task) {
  var env = task.task.payload.env;
  Object.keys(env).forEach(function (name) {
    if (env[name] === "") {
      delete env[name];
    }
  });
});

// Output the final graph.
process.stdout.write(JSON.stringify(graph, null, 2));
