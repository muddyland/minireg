<script setup>
/** Presentational table wrapper: handles the loading / empty / error states so
 *  every view does not reimplement them. */
defineProps({
  columns: { type: Array, required: true },
  rows: { type: Array, default: () => [] },
  loading: { type: Boolean, default: false },
  error: { type: String, default: null },
  emptyText: { type: String, default: 'Nothing to show.' },
  rowKey: { type: String, default: 'id' },
})
</script>

<template>
  <div>
    <div v-if="error" class="alert alert-error">{{ error }}</div>
    <div v-if="loading" class="empty">Loading…</div>
    <div v-else-if="!rows.length" class="empty">{{ emptyText }}</div>
    <div v-else class="table-wrap">
      <table>
        <thead>
          <tr>
            <th v-for="col in columns" :key="col.key" :class="{ num: col.align === 'right' }">
              {{ col.label }}
            </th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="(row, index) in rows" :key="row[rowKey] ?? index">
            <td v-for="col in columns" :key="col.key" :class="{ num: col.align === 'right' }">
              <slot :name="`cell-${col.key}`" :row="row" :value="row[col.key]">
                {{ row[col.key] }}
              </slot>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>
