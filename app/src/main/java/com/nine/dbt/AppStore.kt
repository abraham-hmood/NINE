package com.nine.dbt

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

object AppStore {
    private const val PREFS = "nine_store"

    fun tutorialDone(ctx: Context): Boolean =
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getBoolean("tutorial_done", false)

    fun setTutorialDone(ctx: Context) {
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putBoolean("tutorial_done", true).apply()
    }

    fun useLocal(ctx: Context): Boolean =
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getBoolean("use_local", false)

    fun setUseLocal(ctx: Context, v: Boolean) {
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putBoolean("use_local", v).apply()
    }

    fun localModelUri(ctx: Context): String? =
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString("local_model", null)

    fun localModels(ctx: Context): List<String> {
        val raw = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString("local_models", "") ?: ""
        return raw.split("|").filter { it.isNotBlank() }
    }

    fun saveLocalModels(ctx: Context, models: List<String>) {
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putString("local_models", models.joinToString("|")).apply()
    }

    fun setLocalModelUri(ctx: Context, uri: String) {
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putString("local_model", uri).apply()
        val cur = localModels(ctx).toMutableList()
        if (uri !in cur) cur += uri
        saveLocalModels(ctx, cur)
    }

    fun repositories(ctx: Context): MutableList<Repository> {
        val raw = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString("repos", "[]") ?: "[]"
        val arr = JSONArray(raw)
        val out = mutableListOf<Repository>()
        for (i in 0 until arr.length()) {
            val o = arr.getJSONObject(i)
            out += Repository(o.getString("id"), o.getString("name"), o.getString("url"), o.optString("branch", "main"))
        }
        return out
    }

    fun saveRepositories(ctx: Context, repos: List<Repository>) {
        val arr = JSONArray()
        repos.forEach {
            arr.put(JSONObject().put("id", it.id).put("name", it.name).put("url", it.url).put("branch", it.branch))
        }
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putString("repos", arr.toString()).apply()
    }

    fun cloudModels(ctx: Context): MutableList<CloudModel> {
        val raw = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString("clouds", "[]") ?: "[]"
        val arr = JSONArray(raw)
        val out = mutableListOf<CloudModel>()
        for (i in 0 until arr.length()) {
            val o = arr.getJSONObject(i)
            out += CloudModel(o.getString("id"), o.getString("modelId"), o.getString("url"), o.getString("apiKey"))
        }
        return out
    }

    fun activeCloudId(ctx: Context): String? =
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString("active_cloud", null)

    fun setActiveCloudId(ctx: Context, id: String) {
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putString("active_cloud", id).apply()
    }

    fun activeCloud(ctx: Context): CloudModel? {
        val id = activeCloudId(ctx) ?: return cloudModels(ctx).firstOrNull()
        return cloudModels(ctx).find { it.id == id } ?: cloudModels(ctx).firstOrNull()
    }

    fun deleteCloud(ctx: Context, id: String) {
        val models = cloudModels(ctx).filter { it.id != id }
        saveCloudModels(ctx, models)
        if (activeCloudId(ctx) == id) {
            ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().remove("active_cloud").apply()
        }
    }

    fun saveCloudModels(ctx: Context, models: List<CloudModel>) {
        val arr = JSONArray()
        models.forEach {
            arr.put(JSONObject().put("id", it.id).put("modelId", it.modelId).put("url", it.url).put("apiKey", it.apiKey))
        }
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putString("clouds", arr.toString()).apply()
    }

    fun customTools(ctx: Context): MutableList<AgenticTool> {
        val raw = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString("tools", "[]") ?: "[]"
        val arr = JSONArray(raw)
        val out = mutableListOf<AgenticTool>()
        for (i in 0 until arr.length()) {
            val o = arr.getJSONObject(i)
            val params = mutableListOf<ToolParam>()
            val pa = o.optJSONArray("params") ?: JSONArray()
            for (j in 0 until pa.length()) params += ToolParam(pa.getString(j))
            out += AgenticTool(o.getString("id"), o.getString("name"), o.getString("code"), params, false)
        }
        return out
    }

    fun saveCustomTools(ctx: Context, tools: List<AgenticTool>) {
        val arr = JSONArray()
        tools.filter { !it.isBuiltin }.forEach { t ->
            val pa = JSONArray()
            t.params.forEach { pa.put(it.name) }
            arr.put(JSONObject().put("id", t.id).put("name", t.name).put("code", t.code).put("params", pa))
        }
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putString("tools", arr.toString()).apply()
    }

    // ---------- DLSS-style upscaling / light shell ----------

    fun enableDlss(ctx: Context): Boolean =
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getBoolean("enable_dlss", false)

    fun setEnableDlss(ctx: Context, v: Boolean) {
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putBoolean("enable_dlss", v).apply()
    }

    fun upscalerModelDir(ctx: Context): String? =
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString("upscaler_model_dir", null)

    fun setUpscalerModelDir(ctx: Context, dirPath: String) {
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putString("upscaler_model_dir", dirPath).apply()
    }
}
