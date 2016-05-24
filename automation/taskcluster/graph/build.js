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
      payload: {
        image: process.env.TC_DOCKER_IMAGE,
        maxRunTime: 3600
      },
      metadata: {
        owner: process.env.GITHUB_HEAD_USER_EMAIL,
        source: process.env.GITHUB_HEAD_REPO_URL
      }
    }
  }];

  // Fill in some basic data.
  task.created = from_now(0);
  task.deadline = from_now(24);
  task.provisionerId = process.env.TC_PROVISIONER_ID || "aws-provisioner-v1";
  task.workerType = process.env.TC_WORKER_TYPE || "github-worker";
  task.schedulerId = "task-graph-scheduler";

  // Clone definition.
  def = merge.recursive(true, {}, def);

  // Extend task definition.
  while (def.extends) {
    var base = def.extends;
    delete def.extends;

    var template = doc.templates[base];
    def = merge.recursive(true, template, def);

    if ("name" in template) {
       def.name = template.name + " | " + def.name;
    }
  }

  // Fill in attributes.
  task.metadata.name = def.name;
  task.metadata.description = def.description;
  task.payload.command = def.command;
  task.payload.env = def.env || {};

  // Forward some GitHub env variables.
  task.payload.env.NSS_HEAD_REPOSITORY = process.env.NSS_HEAD_REPOSITORY;
  task.payload.env.NSS_HEAD_REVISION = process.env.NSS_HEAD_REVISION;

  // Register artifacts.
  if (def.artifact) {
    task.payload.artifacts = {
      "public": {
        "type": "directory",
        "path": "/home/worker/artifacts",
        "expires": from_now(1)
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
        subtask.task.metadata.name = task.metadata.name + " | " + subtask.task.metadata.name;
        subtask.task.payload.env = merge.recursive(true, task.payload.env, subtask.task.payload.env);

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
