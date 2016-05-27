/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

var fs = require("fs");
var path = require("path");
var merge = require("merge");
var yaml = require("js-yaml");
var slugid = require("slugid");
var flatmap = require("flatmap");

var TC_WORKER_TYPE = process.env.TC_WORKER_TYPE || "hg-worker";
var TC_PROVISIONER_ID = process.env.TC_PROVISIONER_ID || "aws-provisioner-v1";

// Default values for debugging.
var TC_REVISION = process.env.TC_REVISION || "{{tc_rev}}";
var TC_REVISION_HASH = process.env.TC_REVISION_HASH || "{{tc_rev_hash}}";
var TC_DOCKER_IMAGE = process.env.TC_DOCKER_IMAGE || "{{tc_docker_img}}";
var TC_OWNER = process.env.TC_OWNER || "{{tc_owner}}";
var TC_SOURCE = process.env.TC_SOURCE || "{{tc_source}}";
var NSS_HEAD_REPOSITORY = process.env.NSS_HEAD_REPOSITORY || "{{nss_head_repo}}";
var NSS_HEAD_REVISION = process.env.NSS_HEAD_REVISION || "{{nss_head_rev}}";

// Point in time at $now + x hours.
function from_now(hours) {
  var d = new Date();
  d.setHours(d.getHours() + (hours || 0));
  return d.toJSON();
}

// Register custom YAML types.
var YAML_SCHEMA = yaml.Schema.create([
  new yaml.Type('!from_now', {
    kind: "scalar",

    resolve: function (data) {
      return true;
    },

    construct: function (data) {
      return from_now(data|0);
    }
  })
]);

// Parse a directory containing YAML files.
function parseDirectory(dir) {
  var tasks = {};

  fs.readdirSync(dir).forEach(function (file) {
    if (file.endsWith(".yml")) {
      var source = fs.readFileSync(path.join(dir, file), "utf-8");
      tasks[file.slice(0, -4)] = yaml.load(source, {schema: YAML_SCHEMA});
    }
  });

  return tasks;
}

// Generates a task using a given definition.
function generateTasks(definition) {
  var task = {
    taskId: slugid.v4(),
    reruns: 2,

    task: task = {
      created: from_now(0),
      deadline: from_now(24),
      provisionerId: TC_PROVISIONER_ID,
      workerType: TC_WORKER_TYPE,
      schedulerId: "task-graph-scheduler",

      scopes: [
        "queue:route:tc-treeherder-stage.nss." + TC_REVISION,
        "queue:route:tc-treeherder.nss." + TC_REVISION,
        "scheduler:extend-task-graph:*"
      ],

      routes: [
        "tc-treeherder-stage.nss." + TC_REVISION_HASH,
        "tc-treeherder.nss." + TC_REVISION_HASH
      ],

      metadata: {
        owner: TC_OWNER,
        source: TC_SOURCE
      },

      payload: {
        image: TC_DOCKER_IMAGE,
        maxRunTime: 3600,

        env: {
          NSS_HEAD_REPOSITORY: NSS_HEAD_REPOSITORY,
          NSS_HEAD_REVISION: NSS_HEAD_REVISION
        }
      },

      extra: {
        treeherder: {
          revision: TC_REVISION,
          revision_hash: TC_REVISION_HASH
        }
      }
    }
  };

  // Merge base task definition with the YAML one.
  var tasks = [task = merge.recursive(true, task, definition)];

  // Generate dependent tasks.
  if (task.dependents) {
    // The base definition for all subtasks.
    var base = {
      requires: [task.taskId],

      task: {
        payload: {
          env: {
            TC_PARENT_TASK_ID: task.taskId
          }
        }
      }
    };

    // We clone everything but the taskId, we need a new and unique one.
    delete base.taskId;

    // Iterate and generate all subtasks.
    var subtasks = flatmap(task.dependents, function (name) {
      if (!(name in TASKS)) {
        throw new Error("Can't find task '" + name + "'");
      }

      return flatmap(TASKS[name], function (subtask) {
        // Merge subtask with base definition.
        var dependent = merge.recursive(true, subtask, base);

        // We only want to carry over environment variables and
        // TreeHerder configuration data.
        dependent.task.payload.env =
          merge.recursive(true, task.task.payload.env,
                                dependent.task.payload.env);
        dependent.task.extra.treeherder =
          merge.recursive(true, task.task.extra.treeherder,
                                dependent.task.extra.treeherder);

        // Print all subtasks.
        return generateTasks(dependent);
      });
    });

    // Append subtasks.
    tasks = tasks.concat(subtasks);

    // The dependents field is not part of the schema.
    delete task.dependents;
  }

  return tasks;
}

// Parse YAML task definitions.
var BUILDS = parseDirectory(path.join(__dirname, "./builds/"));
var TASKS = parseDirectory(path.join(__dirname, "./tasks/"));

var graph = {
  // Use files in the "builds" directory as roots.
  tasks: flatmap(Object.keys(BUILDS), function (name) {
    return flatmap(BUILDS[name], function (build) {
      return generateTasks(build);
    });
  })
};

// Output the final graph.
process.stdout.write(JSON.stringify(graph, null, 2));
