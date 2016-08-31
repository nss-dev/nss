/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

var fs = require("fs");
var path = require("path");
var crypto = require("crypto");
var slugid = require("slugid");
var flatmap = require("flatmap");

var yaml = require("./yaml");

// Default values for debugging.
var TC_PROJECT = process.env.TC_PROJECT || "{{tc_project}}";
var NSS_PUSHLOG_ID = process.env.NSS_PUSHLOG_ID || "{{nss_pushlog_id}}";
var NSS_HEAD_REVISION = process.env.NSS_HEAD_REVISION || "{{nss_head_rev}}";

// Add base information to the given task.
function decorateTask(task) {
  // Assign random task id.
  task.taskId = slugid.v4();

  // TreeHerder routes.
  task.task.routes = [
    "tc-treeherder-stage.v2." + TC_PROJECT + "." + NSS_HEAD_REVISION + "." + NSS_PUSHLOG_ID,
    "tc-treeherder.v2." + TC_PROJECT + "." + NSS_HEAD_REVISION + "." + NSS_PUSHLOG_ID
  ];
}

// Compute the SHA-256 digest.
function sha256(data) {
  var hash = crypto.createHash("sha256");
  hash.update(data);
  return hash.digest("hex");
}

// Recursively collect a list of all files of a given directory.
function collectFilesInDirectory(dir) {
  return flatmap(fs.readdirSync(dir), function (entry) {
    var entry_path = path.join(dir, entry);

    if (fs.lstatSync(entry_path).isDirectory()) {
      return collectFilesInDirectory(entry_path);
    }

    return [entry_path];
  });
}

// Compute a hash over the given directory's contents.
function hashDirectory(dir) {
  var files = collectFilesInDirectory(dir).sort();
  var hashes = files.map(function (file) {
    return sha256(file + "|" + fs.readFileSync(file, "utf-8"));
  });

  return sha256(hashes.join(","));
}

// Generates the image-builder task description.
function generateImageBuilderTask(context_path) {
  var root = path.join(__dirname, "../../..");
  var task = yaml.parse(path.join(__dirname, "image_builder.yml"), {});

  // Add base info.
  decorateTask(task);

  // Add info for docker image building.
  task.task.payload.env.CONTEXT_PATH = context_path;
  task.task.payload.env.HASH = hashDirectory(path.join(root, context_path));

  return task;
}

// Tweak the given list of tasks by injecting the image-builder task
// and setting the right dependencies where needed.
function tweakTasks(tasks) {
  var id = "automation/taskcluster/docker";
  var builder_task = generateImageBuilderTask(id);

  tasks.forEach(function (task) {
    if (task.task.payload.image == id) {
      task.task.payload.image = {
        taskId: builder_task.taskId,
        path: "public/image.tar",
        type: "task-image"
      };

      if (!task.requires) {
        task.requires = [builder_task.taskId];
      }
    }
  });

  return [builder_task].concat(tasks);
}

module.exports.tweakTasks = tweakTasks;
