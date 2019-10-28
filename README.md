# OH-SMAP: Leaking Info from Chrome Browser

Recently, Google silently closed many security-related bugs in the `IndexedDB` module of the `Chrome` browser. `IndexedDB` is a database mechanism supported in modern browsers. This module is fairly complicated and in Chrome its logic is implemented in the Browser process and accessible from the Renderer process. Its accessibility from the Renderer makes it a good fit for a Sandbox Escape vector. In this post we discuss one of these bugs and demonstrate how to gain `PutBufferGetAddress` functionality from a compromised Renderer process to the Browser process. 

This functionality basically means an attacker in control of the Renderer process can send controlled data to the Browser and deduce its address in the Browser's memory. Thus bypassing `ASLR` mitigation and general randomness of the heap layout. This primitive assists an attacker to implement a full Sandbox-Escape exploit. We implement our exploit on Android Device with Chrome version 77 (All source code references are from tag `77.0.3865.129`).

The fix for the issue presented below was merged in Chrome 78 version, released on October 22nd 2019. Therefore, users with updated Chrome version are not affected.

## Bug
The bug we exploit is a rather classic example of Time-Of-Check-Time-Of-Use in the Chromium project (the open-source project Google Chrome is derived from). Recall that [synchronization in Chromium](https://chromium.googlesource.com/chromium/src/+/master/docs/threading_and_tasks.md) is based on the concept of `Task Runners` which execute short `Tasks`, i.e. function closures. Longer tasks, or such that require waiting some resources to become available, register a follow-up closure to be executed later. Our subject of investigation is a bug that occurs because some intermediate task changes the state of an object between that initial task and a later task.

Without further ado, let's describe the bug, or rather, the **bugs**, as this pattern repeats in various functions in the same file.
Examine [`IndexedDBDatabase::Get`](https://chromium.googlesource.com/chromium/src/+/refs/tags/77.0.3865.129/content/browser/indexed_db/indexed_db_database.cc#1056) function:
```
void IndexedDBDatabase::Get(
    base::WeakPtr<IndexedDBDispatcherHost> dispatcher_host,
    IndexedDBTransaction* transaction,
    int64_t object_store_id,
    int64_t index_id,
    std::unique_ptr<IndexedDBKeyRange> key_range,
    bool key_only,
    blink::mojom::IDBDatabase::GetCallback callback) {
...
  if (!ValidateObjectStoreIdAndOptionalIndexId(object_store_id, index_id)) {
...
    return;
  }
...
  transaction->ScheduleTask(BindWeakOperation(
      &IndexedDBDatabase::GetOperation, AsWeakPtr(), std::move(dispatcher_host),
      object_store_id, index_id, std::move(key_range),
...
}
```
This function first [validates](https://chromium.googlesource.com/chromium/src/+/refs/tags/77.0.3865.129/content/browser/indexed_db/indexed_db_database.cc#654) the identifiers of the data to get, specifically it verifies that the `object_store_id` exists in the `metadata_.object_stores` map using the `ValidateObjectStoreIdAndOptionalIndexId` method.
```
bool IndexedDBDatabase::ValidateObjectStoreId(int64_t object_store_id) const {
  if (!base::Contains(metadata_.object_stores, object_store_id)) {
    DLOG(ERROR) << "Invalid object_store_id";
    return false;
  }
  return true;
}
...
bool IndexedDBDatabase::ValidateObjectStoreIdAndOptionalIndexId(
    int64_t object_store_id,
    int64_t index_id) const {
  if (!ValidateObjectStoreId(object_store_id))
    return false;
```
Then, it schedules the `IndexedDBDatabase::GetOperation` to be executed later. 

When this function is executed, it blindly [uses this argument](https://chromium.googlesource.com/chromium/src/+/refs/tags/77.0.3865.129/content/browser/indexed_db/indexed_db_database.cc#1100) to access the `ObjectStore` metadata:
```
Status IndexedDBDatabase::GetOperation(
    base::WeakPtr<IndexedDBDispatcherHost> dispatcher_host,
    int64_t object_store_id,
    int64_t index_id,
    std::unique_ptr<IndexedDBKeyRange> key_range,
    indexed_db::CursorType cursor_type,
    blink::mojom::IDBDatabase::GetCallback callback,
    IndexedDBTransaction* transaction) {
  IDB_TRACE1("IndexedDBDatabase::GetOperation", "txn.id", transaction->id());
  DCHECK(metadata_.object_stores.find(object_store_id) !=
         metadata_.object_stores.end());
  const IndexedDBObjectStoreMetadata& object_store_metadata =
      metadata_.object_stores[object_store_id];
```

Therefore, by changing the `metadata_.object_stores` between the the execution of the former function and the latter triggers the bug. Specifically, removing the entry of this `object_store_id` from the map induces a use of uninitialized value (see the [notes about std::map::operator[]](https://en.cppreference.com/w/cpp/container/map/operator_at)).
Effectively, the flow would be equivalent to:
```
metadata_.object_store.remove(object_store_id);
auto &metadata = metadata_.object_store[object_store_id];
```
Note that this pattern exists in almost every function that registers an operation with the `IndexedDBTransaction::ScheduleTask`.

## Trigger
The only thing left to explain is how to change the `metadata_` in the middle. This turns out to be quite easy. The `ScheduleTask` function [adds the function closure to the transaction's `task_queue_`](https://chromium.googlesource.com/chromium/src/+/refs/tags/77.0.3865.129/content/browser/indexed_db/indexed_db_transaction.cc#152) which eventually [posts it to the current `TaskRunner`](https://chromium.googlesource.com/chromium/src/+/refs/tags/77.0.3865.129/content/browser/indexed_db/indexed_db_transaction.cc#178) to be executed later. The `TaskRunner` works in FIFO manner, thus this task is appended to the end of its task queue. If the `TaskRunner` queue already contains an `IndexedDBDatabase::DeleteObjectStoreOperation` it is executed first. This [operation](https://chromium.googlesource.com/chromium/src/+/refs/tags/77.0.3865.129/content/browser/indexed_db/indexed_db_database.cc#2010) deletes the object store from the `metadata_.object_stores` but the `GetOperation` is executed afterwards anyway.

In short, to trigger the bug one has to call `IndexedDBDatabase::DeleteObjectStore` immediately followed by `IndexedDBDatabase::Get` on the same object store. This registers the corresponding operations to execute later unconditionally but the latter acts on the object store after it has been removed from the map.

These functions are accessible from a compromised Renderer almost immediately. The [IndexedDB Mojo Interface](https://chromium.googlesource.com/chromium/src/+/refs/tags/77.0.3865.129/third_party/blink/public/mojom/indexeddb/indexeddb.mojom) (Chromium's IPC mechanism) enables the Renderer process to call the `DeleteObjectStore` and `Get` methods quite easily - by creating an `IDBDatabase` object using the `IDBFactory::Open` and then creating an `IDBTransaction` using the `IDBDatabase::CreateTransaction`. These functions directly invoke the corresponding methods of [`DatabaseImpl`](https://chromium.googlesource.com/chromium/src/+/refs/tags/77.0.3865.129/content/browser/indexed_db/database_impl.h#31) and without any validation call the `IndexedDBDatabase` methods.

## Primitive
Triggering this bug yields a reference to a defaultly constructed `IndexedDBObjectStoreMetadata` object. Here is the [definition](https://chromium.googlesource.com/chromium/src/+/refs/tags/77.0.3865.129/third_party/blink/public/common/indexeddb/indexeddb_metadata.h#19):
```
struct BLINK_COMMON_EXPORT IndexedDBIndexMetadata {
...
  IndexedDBIndexMetadata();
...
  base::string16 name;
  int64_t id;
  blink::IndexedDBKeyPath key_path;
  bool unique;
  bool multi_entry;
};
```
Most of the fields in this struct are initialized to useless default values such as empty strings, but interestingly the integers are not initialized and retain their previous value. However, as the `id` field is saved also as a key, it is barely ever used, therefore actually turning this pathological state to something useful is rather tricky. One of the easier things to do though is to return this `id` to the Renderer by manipulating the Browser to pass the object store's metadata. Passing an uninitialized integer from one context to another is a very effective way to leak pointers and bypass ASLR mitigation. Therefore a tempting goal to achieve.
 
To use this primitive to our needs we want to coerce the Browser process to populate the memory with pointers to controlled data and then free it and let the `IndexedDBObjectStoreMetadata` occupy the same memory area. To do that we need to know the allocation size of that object in memory and understand the allocation mechanism.

## Target Object
At this point, it's time to be more concrete, stop talking about Chromium in general and discuss platform specific details. Our target is to exploit Chrome 77 on modern Android. On this platform Chrome is executed as a 32bit process and uses the `jemalloc` allocator. To understand the memory layout we build the corresponding Chromium configuration for this platform and pass the `-fdump-record-layouts` parameter to the compiler, which emits the layouts of all the structs and classes during the build. The struct we actually instantiate is the node of the underlying tree implementing the map, i.e.:
```
*** Dumping AST Record Layout
0 | class std::__1::__tree_node<struct std::__1::__value_type<long long, struct blink::IndexedDBObjectStoreMetadata>, void *>
...
16 |       const long long first
24 |       struct blink::IndexedDBObjectStoreMetadata second
...
40 |         int64_t id
...
80 |         int64_t max_index_id
...
| [sizeof=104, dsize=104, align=8,
|  nvsize=104, nvalign=8]

```

We can clearly see the `id` field is in offset 40 and the `max_index_id` field is in offset 80. So we need to find a struct that has pointers in the corresponding fields. Also, to complicate matters, this struct deallocation should occur in the same thread and rather soon before the allocation of the uninitialized struct.
After looking for a while, we found the perfect candidate, the `IndexedDBReturnValue` object:
```
*** Dumping AST Record Layout
  0 | struct content::IndexedDBReturnValue
...
 24 |   class blink::IndexedDBKey primary_key
...
 40 |     class std::__1::basic_string<char> binary_
...
 40 |                 std::__1::basic_string<char, struct std::__1::char_traits<char>, class std::__1::allocator<char> >::pointer __data_
 44 |                 std::__1::basic_string<char, struct std::__1::char_traits<char>, class std::__1::allocator<char> >::size_type __size_
 ...
    | [sizeof=112, dsize=108, align=8,
    |  nvsize=108, nvalign=8]
```

As seen, in the relevant offsets this struct has pointers to data which can probably be controlled by the attacker. Namely the [`binary`](https://chromium.googlesource.com/chromium/src/+/refs/tags/77.0.3865.129/third_party/blink/public/mojom/indexeddb/indexeddb.mojom#51) field in the `primary_key` is a pointer to data and the next field is the size of that data which is very indicative.

Since both these structs are allocated using the platform's allocator - `jemalloc`, which rounds up allocation sizes to the next multiple of 0x10, both structs are allocated from the 0x70 size class. `jemalloc` is a complex allocator which is out of scope of this post; for our purposes it is sufficient to say that in those size-classes the allocations are served in a LIFO manner and do not have inline overhead. Therefore in case the last freed allocation of size `(0x60, 0x70]` is the `IndexedDBReturnValue` and the next allocation of that size class is the `IndexedDBObjectStoreMetadata`, then the latter would occupy the same memory.

## Game Plan
It's time to delve into the fine details. Our goal is to coerce the Browser to allocate `IndexedDBReturnValue` with its `primary_key` pointing to our data, then free it, trigger the bug occupying the same memory and then receive the resulting metadata.

We start with populating an IDB database with 2 object stores named `leak` and `vuln`. The first one is the one which causes the allocation of the `IndexedDBReturnValue` object and the second is the one to trigger the vulnerability on. We add an entry to `leak` with a binary key which our leaked address eventually points to.

After this Initial setup, we open the database again with higher version, this initiates an upgrade transaction and calls the `UpgradeNeeded` callback in the Renderer. In this callback we invoke the `DeleteObjectStore` on the `vuln` Object Store, `GetAll` on the `leak` Object Store and finally the `Get` on the `vuln` Object Store. This sequence causes the Browser to schedule all the corresponding operations sequentially and execute them sequentially. The first operation deletes the `vuln` OS and removes it from the `metadata_.object_stores` map. The second operation initializes an [`IndexedDBReturnValue`](https://chromium.googlesource.com/chromium/src/+/refs/tags/77.0.3865.129/content/browser/indexed_db/indexed_db_database.cc#1432) for each value found in the object store - in our case there is only one - filled with our controlled data from the setup stage. Then it pushes it to the `found_values` vector thus allocating it in memory. This allocation is freed when the function returns:
```
Status IndexedDBDatabase::GetAllOperation(
...
) {
...
  std::vector<IndexedDBReturnValue> found_values;
...
  while (num_found_items++ < max_count) {
...
    IndexedDBReturnValue return_value;
...
    found_values.push_back(return_value);
  }
...
}
```
The last operation allocates the uninitialized object. When the transaction is committed, the `SuccessDatabase` callback is called in the Renderer with the database's metadata, including the OS map (OH-Smap?) that contains the uninitialized values.

## Implementation
Fortunately, implementing this exploit doesn't require writing native code or elaborate schemes. It can be implemented purely in JS. The only thing needed is to enable the Mojo JS bindings. This can be done by specifying the `--enable-blink-features=MojoJS` flag when executing chrome or by using a JS RCE exploit. After the bindings are available we can implement our plan using the generated Mojo code.

You can find the POC [in our Github repo](https://github.com/bindecy/ohsmap/blob/master/exploit.js).

To verify that the exploit indeed causes our buffer to be allocated in the leaked address one needs a rooted device or a full Sandbox-Escape exploit, but this is a story for another day. To give you a hint, take a look at [this bug](https://bugs.chromium.org/p/project-zero/issues/detail?id=1912&can=1&q=markbrand%40google.com&sort=-reported&colspec=ID%20Status%20Restrict%20Reported%20Vendor%20Product%20Finder%20Summary) and maybe if you look close enough, you will find a way to combine it with what you have learned today to fully control the Browser process.

## Final Words
We demonstrate in this post how an attacker can put controlled data in Chrome's Browser process from a compromised Renderer process and then leak this data's address. While insufficient for complete escape, this exploit is an important tool in the attacker's toolbox, as it bypasses the notorious ASLR mitigation and overcome common reliability issues in exploit development.
 
Interestingly, this bug has been already [fixed](https://chromium.googlesource.com/chromium/src/+/0240b781039c83aa458e6ff72f2c0db9a18092eb%5E%21/content/browser/indexed_db/indexed_db_database.cc) two months ago, but only with the release of Version 78 in the last few days users are protected against the exploitation of this bug. Two months is quite a long gap to and gives attackers a window of opportunity to exploit this bug in the meantime.
Hopefully in the future this patch gap will be much shorter and users security will increase.
