---
layout: post

title: "Cinder创建卷源码分析(Queens)"

subtitle: ""

date: 2018-07-15 17:08:00

author:     "Jobin"
header-img: "img/post-bg-2018-715.png"
catalog: true
tags:
    - Cinder-create-volume
---

# Cinder创建卷源码分析（Queens）

## cinder api部分

cinder/api/v3/volumes.py

```python
class VolumeController(volumes_v2.VolumeController):
    """The Volumes API controller for the OpenStack API V3."""
    ......
    @wsgi.response(http_client.ACCEPTED)
    def create(self, req, body):
        """Creates a new volume.

        :param req: the request
        :param body: the request body
        :returns: dict -- the new volume dictionary
        :raises HTTPNotFound, HTTPBadRequest:
        """
        self.assert_valid_body(body, 'volume')

        LOG.debug('Create volume request body: %s', body)
        context = req.environ['cinder.context']

        req_version = req.api_version_request
        # Remove group_id from body if max version is less than GROUP_VOLUME.
        if req_version.matches(None, mv.get_prior_version(mv.GROUP_VOLUME)):
            # NOTE(xyang): The group_id is from a group created with a
            # group_type. So with this group_id, we've got a group_type
            # for this volume. Also if group_id is passed in, that means
            # we already know which backend is hosting the group and the
            # volume will be created on the same backend as well. So it
            # won't go through the scheduler again if a group_id is
            # passed in.
            try:
                body.get('volume', {}).pop('group_id', None)
            except AttributeError:
                msg = (_("Invalid body provided for creating volume. "
                         "Request API version: %s.") % req_version)
                raise exc.HTTPBadRequest(explanation=msg)

        volume = body['volume']
        kwargs = {}
        self.validate_name_and_description(volume)

        # Check up front for legacy replication parameters to quick fail
        source_replica = volume.get('source_replica')
        if source_replica:
            msg = _("Creating a volume from a replica source was part of the "
                    "replication v1 implementation which is no longer "
                    "available.")
            raise exception.InvalidInput(reason=msg)

        # NOTE(thingee): v2 API allows name instead of display_name
        if 'name' in volume:
            volume['display_name'] = volume.pop('name')

        # NOTE(thingee): v2 API allows description instead of
        #                display_description
        if 'description' in volume:
            volume['display_description'] = volume.pop('description')

        if 'image_id' in volume:
            volume['imageRef'] = volume.pop('image_id')

        req_volume_type = volume.get('volume_type', None)
        if req_volume_type:
            # Not found exception will be handled at the wsgi level
            kwargs['volume_type'] = (
                objects.VolumeType.get_by_name_or_id(context, req_volume_type))

        kwargs['metadata'] = volume.get('metadata', None)

        snapshot_id = volume.get('snapshot_id')
        if snapshot_id is not None:
            if not uuidutils.is_uuid_like(snapshot_id):
                msg = _("Snapshot ID must be in UUID form.")
                raise exc.HTTPBadRequest(explanation=msg)
            # Not found exception will be handled at the wsgi level
            kwargs['snapshot'] = self.volume_api.get_snapshot(context,
                                                              snapshot_id)
        else:
            kwargs['snapshot'] = None

        source_volid = volume.get('source_volid')
        if source_volid is not None:
            if not uuidutils.is_uuid_like(source_volid):
                msg = _("Source volume ID '%s' must be a "
                        "valid UUID.") % source_volid
                raise exc.HTTPBadRequest(explanation=msg)
            # Not found exception will be handled at the wsgi level
            kwargs['source_volume'] = (
                self.volume_api.get_volume(context,
                                           source_volid))
        else:
            kwargs['source_volume'] = None

        kwargs['group'] = None
        kwargs['consistencygroup'] = None
        consistencygroup_id = volume.get('consistencygroup_id')
        if consistencygroup_id is not None:
            if not uuidutils.is_uuid_like(consistencygroup_id):
                msg = _("Consistency group ID '%s' must be a "
                        "valid UUID.") % consistencygroup_id
                raise exc.HTTPBadRequest(explanation=msg)
            # Not found exception will be handled at the wsgi level
            kwargs['group'] = self.group_api.get(context, consistencygroup_id)

        # Get group_id if volume is in a group.
        group_id = volume.get('group_id')
        if group_id is not None:
            # Not found exception will be handled at the wsgi level
            kwargs['group'] = self.group_api.get(context, group_id)

        # self.ext_mgr: <cinder.api.extensions.ExtensionManager object at 0x7f8d51ee9910>
        # 'os-image-create': <cinder.api.contrib.image_create.Image_create object at 0x7f8d51e724d0>
        if self.ext_mgr.is_loaded('os-image-create'):
            image_ref = volume.get('imageRef')
            if image_ref is not None:
                image_uuid = self._image_uuid_from_ref(image_ref, context)
                image_snapshot = self._get_image_snapshot(context, image_uuid)
                if (req_version.matches(mv.get_api_version(
                        mv.SUPPORT_NOVA_IMAGE)) and image_snapshot):
                    kwargs['snapshot'] = image_snapshot
                else:
                    kwargs['image_id'] = image_uuid

        # Add backup if min version is greater than or equal
        # to VOLUME_CREATE_FROM_BACKUP.
        if req_version.matches(mv.VOLUME_CREATE_FROM_BACKUP, None):
            backup_id = volume.get('backup_id')
            if backup_id:
                if not uuidutils.is_uuid_like(backup_id):
                    msg = _("Backup ID must be in UUID form.")
                    raise exc.HTTPBadRequest(explanation=msg)
                kwargs['backup'] = self.backup_api.get(context,
                                                       backup_id=backup_id)
            else:
                kwargs['backup'] = None

        size = volume.get('size', None)
        if size is None and kwargs['snapshot'] is not None:
            size = kwargs['snapshot']['volume_size']
        elif size is None and kwargs['source_volume'] is not None:
            size = kwargs['source_volume']['size']
        elif size is None and kwargs.get('backup') is not None:
            size = kwargs['backup']['size']

        LOG.info("Create volume of %s GB", size)

        kwargs['availability_zone'] = volume.get('availability_zone', None)
        kwargs['scheduler_hints'] = volume.get('scheduler_hints', None)
        multiattach = volume.get('multiattach', False)
        kwargs['multiattach'] = multiattach

        if multiattach:
            msg = ("The option 'multiattach' "
                   "is deprecated and will be removed in a future "
                   "release.  The default behavior going forward will "
                   "be to specify mulitattach enabled volume types.")
            versionutils.report_deprecated_feature(LOG, msg)

        new_volume = self.volume_api.create(context,
                                            size,
                                            volume.get('display_name'),
                                            volume.get('display_description'),
                                            **kwargs)

        retval = self._view_builder.detail(req, new_volume)

        return retval
    ......
```

对volume type进行检查objects.VolumeType.get_by_name_or_id

cinder/objects/volume_type.py

```python
@base.CinderObjectRegistry.register
class VolumeType(base.CinderPersistentObject, base.CinderObject,
                 base.CinderObjectDictCompat, base.CinderComparableObject):
    ......
    @classmethod
    def get_by_name_or_id(cls, context, identity):
        orm_obj = volume_types.get_by_name_or_id(context, identity)
        expected_attrs = cls._get_expected_attrs(context)
        return cls._from_db_object(context, cls(context),
                                   orm_obj, expected_attrs=expected_attrs)
    ......
```

cinder/volume/volume_types.py

```python
def get_by_name_or_id(context, identity):
    """Retrieves volume type by id or name"""
    if not uuidutils.is_uuid_like(identity):
        return get_volume_type_by_name(context, identity)
    return get_volume_type(context, identity)

def get_volume_type_by_name(context, name):
    """Retrieves single volume type by name."""
    # name: u'volume_high_triple'
    if name is None:
        msg = _("name cannot be None")
        raise exception.InvalidVolumeType(reason=msg)

    return db.volume_type_get_by_name(context, name)
```

cinder/db/api.py

```python
_BACKEND_MAPPING = {'sqlalchemy': 'cinder.db.sqlalchemy.api'}

IMPL = oslo_db_api.DBAPI.from_config(conf=CONF,
                                     backend_mapping=_BACKEND_MAPPING,
                                     lazy=True)

def volume_type_get_by_name(context, name):
    """Get volume type by name."""
    return IMPL.volume_type_get_by_name(context, name)
```

cinder/db/sqlalchemy/api.py

```python
@require_context
def volume_type_get_by_name(context, name):
    """Return a dict describing specific volume_type."""

    return _volume_type_get_by_name(context, name)

......
@require_context
def _volume_type_get_by_name(context, name, session=None):
    # <cinder.db.sqlalchemy.models.VolumeTypes object at 0x7f5c0d66b4d0>
    result = model_query(context, models.VolumeTypes, session=session).\
        options(joinedload('extra_specs')).\
        filter_by(name=name).\
        first()

    if not result:
        raise exception.VolumeTypeNotFoundByName(volume_type_name=name)

    return _dict_with_extra_specs_if_authorized(context, result)
......
```

cinder/db/sqlalchemy/api.py

```python
def _dict_with_extra_specs_if_authorized(context, inst_type_query):
    """Convert type query result to dict with extra_spec and rate_limit.

    Takes a volume type query returned by sqlalchemy and returns it
    as a dictionary, converting the extra_specs entry from a list
    of dicts.  NOTE the contents of extra-specs are admin readable
    only.  If the context passed in for this request is not admin
    then we will return an empty extra-specs dict rather than
    providing the admin only details.

    Example response with admin context:

    'extra_specs' : [{'key': 'k1', 'value': 'v1', ...}, ...]
    to a single dict:
    'extra_specs' : {'k1': 'v1'}

    """

    # {'name': u'volume_high_triple', 'qos_specs_id': None, 'deleted': False, 'created_at': datetime.datetime(2018, 7, 2, 11, 20, 51), 'updated_at': None, 'extra_specs': [<cinder.db.sqlalchemy.models.VolumeTypeExtraSpecs object at 0x7f5c0d66b350>], 'is_public': True, 'deleted_at': None, 'id': u'8e8aaa74-30a8-45ed-b378-0ff414e48129', 'description': u'\u6027\u80fd\u578b'}
    inst_type_dict = dict(inst_type_query)

    extra_specs = {x['key']: x['value']
                   for x in inst_type_query['extra_specs']}
    inst_type_dict['extra_specs'] = extra_specs

    # {'name': u'volume_high_triple', 'qos_specs_id': None, 'deleted': False, 'created_at': datetime.datetime(2018, 7, 2, 11, 20, 51), 'updated_at': None, 'extra_specs': {u'volume_backend_name': u'volume_high_triple'}, 'is_public': True, 'deleted_at': None, 'id': u'8e8aaa74-30a8-45ed-b378-0ff414e48129', 'description': u'\u6027\u80fd\u578b'}
    return inst_type_dict
```

上面分析了volume_type的获取过程。

下面分析创建卷的过程self.volume_api.create

cinder/volume/api.py

```python
class API(base.Base):
    """API for interacting with the volume manager."""
    ......
    def create(self, context, size, name, description, snapshot=None,
               image_id=None, volume_type=None, metadata=None,
               availability_zone=None, source_volume=None,
               scheduler_hints=None,
               source_replica=None, consistencygroup=None,
               cgsnapshot=None, multiattach=False, source_cg=None,
               group=None, group_snapshot=None, source_group=None,
               backup=None):

        if image_id:
            context.authorize(vol_policy.CREATE_FROM_IMAGE_POLICY)
        else:
            context.authorize(vol_policy.CREATE_POLICY)

        # Check up front for legacy replication parameters to quick fail
        if source_replica:
            msg = _("Creating a volume from a replica source was part of the "
                    "replication v1 implementation which is no longer "
                    "available.")
            raise exception.InvalidInput(reason=msg)

        # NOTE(jdg): we can have a create without size if we're
        # doing a create from snap or volume.  Currently
        # the taskflow api will handle this and pull in the
        # size from the source.

        # NOTE(jdg): cinderclient sends in a string representation
        # of the size value.  BUT there is a possibility that somebody
        # could call the API directly so the is_int_like check
        # handles both cases (string representation of true float or int).
        if size and (not strutils.is_int_like(size) or int(size) <= 0):
            msg = _('Invalid volume size provided for create request: %s '
                    '(size argument must be an integer (or string '
                    'representation of an integer) and greater '
                    'than zero).') % size
            raise exception.InvalidInput(reason=msg)

        if consistencygroup and (not cgsnapshot and not source_cg):
            if not volume_type:
                msg = _("volume_type must be provided when creating "
                        "a volume in a consistency group.")
                raise exception.InvalidInput(reason=msg)
            cg_voltypeids = consistencygroup.volume_type_id
            if volume_type.id not in cg_voltypeids:
                msg = _("Invalid volume_type provided: %s (requested "
                        "type must be supported by this consistency "
                        "group).") % volume_type
                raise exception.InvalidInput(reason=msg)

        if group and (not group_snapshot and not source_group):
            if not volume_type:
                msg = _("volume_type must be provided when creating "
                        "a volume in a group.")
                raise exception.InvalidInput(reason=msg)
            vol_type_ids = [v_type.id for v_type in group.volume_types]
            if volume_type.id not in vol_type_ids:
                msg = _("Invalid volume_type provided: %s (requested "
                        "type must be supported by this "
                        "group).") % volume_type
                raise exception.InvalidInput(reason=msg)

        if source_volume and volume_type:
            if volume_type.id != source_volume.volume_type_id:
                if not self._retype_is_possible(
                        context,
                        source_volume.volume_type,
                        volume_type):
                    msg = _("Invalid volume_type provided: %s (requested type "
                            "is not compatible; either match source volume, "
                            "or omit type argument).") % volume_type.id
                    raise exception.InvalidInput(reason=msg)

        if snapshot and volume_type:
            if volume_type.id != snapshot.volume_type_id:
                if not self._retype_is_possible(context,
                                                snapshot.volume.volume_type,
                                                volume_type):
                    msg = _("Invalid volume_type provided: %s (requested "
                            "type is not compatible; recommend omitting "
                            "the type argument).") % volume_type.id
                    raise exception.InvalidInput(reason=msg)

        # Determine the valid availability zones that the volume could be
        # created in (a task in the flow will/can use this information to
        # ensure that the availability zone requested is valid).
        # raw_zones: ({'available': True, 'name': u'nova'},)
        raw_zones = self.list_availability_zones(enable_cache=True)
        # availability_zones: set([u'nova'])
        availability_zones = set([az['name'] for az in raw_zones])
        if CONF.storage_availability_zone:
            availability_zones.add(CONF.storage_availability_zone)

        utils.check_metadata_properties(metadata)

        if (volume_type and self._is_multiattach(volume_type)) or multiattach:
            context.authorize(vol_policy.MULTIATTACH_POLICY)

        # {'scheduler_hints': {}, 'group': None, 'raw_size': 10, 'multiattach': False, 'cgsnapshot': None, 'description': u'', 'source_group': None, 'source_volume': None, 'group_snapshot': None, 'consistencygroup': None, 'image_id': None, 'snapshot': None, 'optional_args': {'is_quota_committed': False}, 'context': <cinder.context.RequestContext object at 0x7f8d51a8f090>, 'raw_availability_zone': None, 'metadata': {u'hik_system_volume': u'false'}, 'backup': None, 'raw_volume_type': VolumeType(created_at=2018-07-02T11:20:51Z,deleted=False,deleted_at=None,description='性能型',extra_specs={volume_backend_name='volume_high_triple'},id=8e8aaa74-30a8-45ed-b378-0ff414e48129,is_public=True,name='volume_high_triple',projects=[],qos_specs=<?>,qos_specs_id=None,updated_at=None), 'key_manager': <castellan.key_manager.barbican_key_manager.BarbicanKeyManager object at 0x7f8d51df1590>, 'name': u'test'}
        create_what = {
            'context': context,
            'raw_size': size,
            'name': name,
            'description': description,
            'snapshot': snapshot,
            'image_id': image_id,
            'raw_volume_type': volume_type,
            'metadata': metadata or {},
            'raw_availability_zone': availability_zone,
            'source_volume': source_volume,
            'scheduler_hints': scheduler_hints,
            'key_manager': self.key_manager,
            'optional_args': {'is_quota_committed': False},
            'consistencygroup': consistencygroup,
            'cgsnapshot': cgsnapshot,
            'multiattach': multiattach,
            'group': group,
            'group_snapshot': group_snapshot,
            'source_group': source_group,
            'backup': backup,
        }
        try:
            # <cinder.scheduler.rpcapi.SchedulerAPI object at 0x7f8d51e72dd0>
            sched_rpcapi = (self.scheduler_rpcapi if (
                            not cgsnapshot and not source_cg and
                            not group_snapshot and not source_group)
                            else None)
            # <cinder.volume.rpcapi.VolumeAPI object at 0x7f8d51df1150>
            volume_rpcapi = (self.volume_rpcapi if (
                             not cgsnapshot and not source_cg and
                             not group_snapshot and not source_group)
                             else None)
            # <taskflow.engines.action_engine.engine.SerialActionEngine object at 0x7f8d516603d0>
            flow_engine = create_volume.get_flow(self.db,
                                                 self.image_service,
                                                 availability_zones,
                                                 create_what,
                                                 sched_rpcapi,
                                                 volume_rpcapi)
        except Exception:
            msg = _('Failed to create api volume flow.')
            LOG.exception(msg)
            raise exception.CinderException(msg)

        # Attaching this listener will capture all of the notifications that
        # taskflow sends out and redirect them to a more useful log for
        # cinders debugging (or error reporting) usage.
        with flow_utils.DynamicLogListener(flow_engine, logger=LOG):
            try:
                flow_engine.run()
                vref = flow_engine.storage.fetch('volume')
                # NOTE(tommylikehu): If the target az is not hit,
                # refresh the az cache immediately.
                if flow_engine.storage.fetch('refresh_az'):
                    self.list_availability_zones(enable_cache=True,
                                                 refresh_cache=True)
                # Refresh the object here, otherwise things ain't right
                vref = objects.Volume.get_by_id(
                    context, vref['id'])
                vref.multiattach = (self._is_multiattach(volume_type) or
                                    multiattach)
                vref.save()
                LOG.info("Create volume request issued successfully.",
                         resource=vref)
                return vref
            except exception.InvalidAvailabilityZone:
                with excutils.save_and_reraise_exception():
                    self.list_availability_zones(enable_cache=True,
                                                 refresh_cache=True)
    ......
```

cinder/volume/flows/api/create_volume.py

```python
def get_flow(db_api, image_service_api, availability_zones, create_what,
             scheduler_rpcapi=None, volume_rpcapi=None):
    """Constructs and returns the api entrypoint flow.

    This flow will do the following:

    1. Inject keys & values for dependent tasks.
    2. Extracts and validates the input keys & values.
    3. Reserves the quota (reverts quota on any failures).
    4. Creates the database entry.
    5. Commits the quota.
    6. Casts to volume manager or scheduler for further processing.
    """
    # db_api: <module 'cinder.db' from '/usr/lib/python2.7/site-packages/cinder/db/__init__.pyc'>
    # image_service_api: <cinder.image.glance.GlanceImageService object at 0x7f8d51e72c90>
    # availability_zones: set([u'nova'])
    # scheduler_rpcapi: <cinder.scheduler.rpcapi.SchedulerAPI object at 0x7f8d51e72dd0>
    # volume_rpcapi: <cinder.volume.rpcapi.VolumeAPI object at 0x7f8d51df1150>
    # flow_name: 'volume_create_api'
    flow_name = ACTION.replace(":", "_") + "_api"
    api_flow = linear_flow.Flow(flow_name)

    api_flow.add(ExtractVolumeRequestTask(
        image_service_api,
        availability_zones,
        rebind={'size': 'raw_size',
                'availability_zone': 'raw_availability_zone',
                'volume_type': 'raw_volume_type'}))
    api_flow.add(QuotaReserveTask(),
                 EntryCreateTask(),
                 QuotaCommitTask())

    if scheduler_rpcapi and volume_rpcapi:
        # This will cast it out to either the scheduler or volume manager via
        # the rpc apis provided.
        api_flow.add(VolumeCastTask(scheduler_rpcapi, volume_rpcapi, db_api))

    # Now load (but do not run) the flow using the provided initial data.
    return taskflow.engines.load(api_flow, store=create_what)
```

将任务添加到api_flow中

taskflow/patterns/linear_flow.py

```python
class Flow(flow.Flow):
    """Linear flow pattern.

    A linear (potentially nested) flow of *tasks/flows* that can be
    applied in order as one unit and rolled back as one unit using
    the reverse order that the *tasks/flows* have been applied in.
    """
    
    ......
    def add(self, *items):
        """Adds a given task/tasks/flow/flows to this flow."""
        for item in items:
            if not self._graph.has_node(item):
                self._graph.add_node(item)
                if self._last_item is not self._no_last_item:
                    self._graph.add_edge(self._last_item, item,
                                         attr_dict={flow.LINK_INVARIANT: True})
                self._last_item = item
        return self
    ......
```

任务流引擎加载flow

taskflow/engines/helpers.py

```python
def load(flow, store=None, flow_detail=None, book=None,
         backend=None, namespace=ENGINES_NAMESPACE,
         engine=ENGINE_DEFAULT, **kwargs):
    """Load a flow into an engine.

    This function creates and prepares an engine to run the provided flow. All
    that is left after this returns is to run the engine with the
    engines :py:meth:`~taskflow.engines.base.Engine.run` method.

    Which engine to load is specified via the ``engine`` parameter. It
    can be a string that names the engine type to use, or a string that
    is a URI with a scheme that names the engine type to use and further
    options contained in the URI's host, port, and query parameters...

    Which storage backend to use is defined by the backend parameter. It
    can be backend itself, or a dictionary that is passed to
    :py:func:`~taskflow.persistence.backends.fetch` to obtain a
    viable backend.

    :param flow: flow to load
    :param store: dict -- data to put to storage to satisfy flow requirements
    :param flow_detail: FlowDetail that holds the state of the flow (if one is
        not provided then one will be created for you in the provided backend)
    :param book: LogBook to create flow detail in if flow_detail is None
    :param backend: storage backend to use or configuration that defines it
    :param namespace: driver namespace for stevedore (or empty for default)
    :param engine: string engine type or URI string with scheme that contains
                   the engine type and any URI specific components that will
                   become part of the engine options.
    :param kwargs: arbitrary keyword arguments passed as options (merged with
                   any extracted ``engine``), typically used for any engine
                   specific options that do not fit as any of the
                   existing arguments.
    :returns: engine
    """

    kind, options = _extract_engine(engine, **kwargs)

    if isinstance(backend, dict):
        backend = p_backends.fetch(backend)

    if flow_detail is None:
        # <taskflow.persistence.models.FlowDetail object at 0x7f8d5119c1d0>
        flow_detail = p_utils.create_flow_detail(flow, book=book,
                                                 backend=backend)

    LOG.debug('Looking for %r engine driver in %r', kind, namespace)
    try:
        mgr = stevedore.driver.DriverManager(
            namespace, kind,
            invoke_on_load=True,
            invoke_args=(flow, flow_detail, backend, options))
        engine = mgr.driver
    except RuntimeError as e:
        raise exc.NotFound("Could not find engine '%s'" % (kind), e)
    else:
        if store:
            engine.storage.inject(store)
        return engine
```

前面分析了任务流的加载过程，下面分析任务流的运行过程，首先分析EntryCreateTask()，EntryCreateTask会将卷的创建过程写入数据库，此时卷的状态为“creating”

cinder/volume/flows/api/create_volume.py

```python
class EntryCreateTask(flow_utils.CinderTask):
    """Creates an entry for the given volume creation in the database.

    Reversion strategy: remove the volume_id created from the database.
    """

    default_provides = set(['volume_properties', 'volume_id', 'volume'])

    def __init__(self):
        requires = ['availability_zone', 'description', 'metadata',
                    'name', 'reservations', 'size', 'snapshot_id',
                    'source_volid', 'volume_type_id', 'encryption_key_id',
                    'consistencygroup_id', 'cgsnapshot_id', 'multiattach',
                    'qos_specs', 'group_id', ]
        super(EntryCreateTask, self).__init__(addons=[ACTION],
                                              requires=requires)

    def execute(self, context, optional_args, **kwargs):
        """Creates a database entry for the given inputs and returns details.

        Accesses the database and creates a new entry for the to be created
        volume using the given volume properties which are extracted from the
        input kwargs (and associated requirements this task needs). These
        requirements should be previously satisfied and validated by a
        pre-cursor task.
        """

        src_volid = kwargs.get('source_volid')
        src_vol = None
        if src_volid is not None:
            src_vol = objects.Volume.get_by_id(context, src_volid)
        bootable = False
        if src_vol is not None:
            bootable = src_vol.bootable

        volume_properties = {
            'size': kwargs.pop('size'),
            'user_id': context.user_id,
            'project_id': context.project_id,
            'status': 'creating',
            'attach_status': fields.VolumeAttachStatus.DETACHED,
            'encryption_key_id': kwargs.pop('encryption_key_id'),
            # Rename these to the internal name.
            'display_description': kwargs.pop('description'),
            'display_name': kwargs.pop('name'),
            'multiattach': kwargs.pop('multiattach'),
            'bootable': bootable,
        }

        # Merge in the other required arguments which should provide the rest
        # of the volume property fields (if applicable).
        volume_properties.update(kwargs)
        volume = objects.Volume(context=context, **volume_properties)
        volume.create()

        # FIXME(dulek): We're passing this volume_properties dict through RPC
        # in request_spec. This shouldn't be needed, most data is replicated
        # in both volume and other places. We should make Newton read data
        # from just one correct place and leave just compatibility code.
        #
        # Right now - let's move it to versioned objects to be able to make
        # non-backward compatible changes.

        volume_properties = objects.VolumeProperties(**volume_properties)

        return {
            'volume_id': volume['id'],
            'volume_properties': volume_properties,
            # NOTE(harlowja): it appears like further usage of this volume
            # result actually depend on it being a sqlalchemy object and not
            # just a plain dictionary so that's why we are storing this here.
            #
            # In the future where this task results can be serialized and
            # restored automatically for continued running we will need to
            # resolve the serialization & recreation of this object since raw
            # sqlalchemy objects can't be serialized.
            'volume': volume,
        }
```

volume.create()

cinder/objects/volume.py

```python
@base.CinderObjectRegistry.register
class Volume(cleanable.CinderCleanableObject, base.CinderObject,
             base.CinderObjectDictCompat, base.CinderComparableObject,
             base.ClusteredObject):
    
    ......
    def create(self):
        if self.obj_attr_is_set('id'):
            raise exception.ObjectActionError(action='create',
                                              reason=_('already created'))
        updates = self.cinder_obj_get_changes()

        if 'consistencygroup' in updates:
            raise exception.ObjectActionError(
                action='create', reason=_('consistencygroup assigned'))
        if 'snapshots' in updates:
            raise exception.ObjectActionError(
                action='create', reason=_('snapshots assigned'))
        if 'cluster' in updates:
            raise exception.ObjectActionError(
                action='create', reason=_('cluster assigned'))
        if 'group' in updates:
            raise exception.ObjectActionError(
                action='create', reason=_('group assigned'))

        db_volume = db.volume_create(self._context, updates)
        self._from_db_object(self._context, self, db_volume)
    ......
```

db.volume_create

cinder/db/api.py

```python
_BACKEND_MAPPING = {'sqlalchemy': 'cinder.db.sqlalchemy.api'}


IMPL = oslo_db_api.DBAPI.from_config(conf=CONF,
                                     backend_mapping=_BACKEND_MAPPING,
                                     lazy=True)

def volume_create(context, values):
    """Create a volume from the values dictionary."""
    return IMPL.volume_create(context, values)
```

oslo_db_api.DBAPI.from_config

oslo_db/api.py

```python
class DBAPI(object):
    """Initialize the chosen DB API backend."""
    ......
    @classmethod
    def from_config(cls, conf, backend_mapping=None, lazy=False):
        """Initialize DBAPI instance given a config instance.

        :param conf: oslo.config config instance
        :type conf: oslo.config.cfg.ConfigOpts

        :param backend_mapping: backend name -> module/class to load mapping
        :type backend_mapping: dict

        :param lazy: load the DB backend lazily on the first DB API method call
        :type lazy: bool

        """

        conf.register_opts(options.database_opts, 'database')

        return cls(backend_name=conf.database.backend,
                   backend_mapping=backend_mapping,
                   lazy=lazy,
                   use_db_reconnect=conf.database.use_db_reconnect,
                   retry_interval=conf.database.db_retry_interval,
                   inc_retry_interval=conf.database.db_inc_retry_interval,
                   max_retry_interval=conf.database.db_max_retry_interval,
                   max_retries=conf.database.db_max_retries)
    ......
```

IMPL.volume_create

cinder/db/sqlalchemy/api.py

```python
@handle_db_data_error
@require_context
def volume_create(context, values):
    values['volume_metadata'] = _metadata_refs(values.get('metadata'),
                                               models.VolumeMetadata)
    if is_admin_context(context):
        values['volume_admin_metadata'] = \
            _metadata_refs(values.get('admin_metadata'),
                           models.VolumeAdminMetadata)
    elif values.get('volume_admin_metadata'):
        del values['volume_admin_metadata']

    volume_ref = models.Volume()
    if not values.get('id'):
        values['id'] = str(uuid.uuid4())
    volume_ref.update(values)

    session = get_session()
    with session.begin():
        session.add(volume_ref)

    return _volume_get(context, values['id'], session=session)
```

下面分析VolumeCastTask

cinder/volume/flows/api/create_volume.py

```python
class VolumeCastTask(flow_utils.CinderTask):
    """Performs a volume create cast to the scheduler or to the volume manager.

    This will signal a transition of the api workflow to another child and/or
    related workflow on another component.

    Reversion strategy: rollback source volume status and error out newly
    created volume.
    """
    ......
    def execute(self, context, **kwargs):
        scheduler_hints = kwargs.pop('scheduler_hints', None)
        db_vt = kwargs.pop('volume_type')
        kwargs['volume_type'] = None
        if db_vt:
            kwargs['volume_type'] = objects.VolumeType()
            objects.VolumeType()._from_db_object(context,
                                                 kwargs['volume_type'], db_vt)
        request_spec = objects.RequestSpec(**kwargs)
        filter_properties = {}
        if scheduler_hints:
            filter_properties['scheduler_hints'] = scheduler_hints
        self._cast_create_volume(context, request_spec, filter_properties)
    ......
```

self._cast_create_volume

cinder/volume/flows/api/create_volume.py

```python
def _cast_create_volume(self, context, request_spec, filter_properties):
        source_volid = request_spec['source_volid']
        volume = request_spec['volume']
        snapshot_id = request_spec['snapshot_id']
        image_id = request_spec['image_id']
        cgroup_id = request_spec['consistencygroup_id']
        group_id = request_spec['group_id']
        backup_id = request_spec['backup_id']
        if cgroup_id:
            # If cgroup_id existed, we should cast volume to the scheduler
            # to choose a proper pool whose backend is same as CG's backend.
            cgroup = objects.ConsistencyGroup.get_by_id(context, cgroup_id)
            request_spec['resource_backend'] = vol_utils.extract_host(
                cgroup.host)
        elif group_id:
            # If group_id exists, we should cast volume to the scheduler
            # to choose a proper pool whose backend is same as group's backend.
            group = objects.Group.get_by_id(context, group_id)
            request_spec['resource_backend'] = vol_utils.extract_host(
                group.host)
        elif snapshot_id and CONF.snapshot_same_host:
            # NOTE(Rongze Zhu): A simple solution for bug 1008866.
            #
            # If snapshot_id is set and CONF.snapshot_same_host is True, make
            # the call create volume directly to the volume host where the
            # snapshot resides instead of passing it through the scheduler, so
            # snapshot can be copied to the new volume.
            # NOTE(tommylikehu): In order to check the backend's capacity
            # before creating volume, we schedule this request to scheduler
            # service with the desired backend information.
            snapshot = objects.Snapshot.get_by_id(context, snapshot_id)
            request_spec['resource_backend'] = snapshot.volume.host
        elif source_volid:
            source_volume_ref = objects.Volume.get_by_id(context, source_volid)
            request_spec['resource_backend'] = source_volume_ref.host

        self.scheduler_rpcapi.create_volume(
            context,
            volume,
            snapshot_id=snapshot_id,
            image_id=image_id,
            request_spec=request_spec,
            filter_properties=filter_properties,
            backup_id=backup_id)
```

self.scheduler_rpcapi.create_volume

cinder/scheduler/rpcapi.py

```python
class SchedulerAPI(rpc.RPCAPI):
    """Client side of the scheduler RPC API."""
    ......
    def create_volume(self, ctxt, volume, snapshot_id=None, image_id=None,
                      request_spec=None, filter_properties=None,
                      backup_id=None):
        volume.create_worker()
        cctxt = self._get_cctxt()
        msg_args = {'snapshot_id': snapshot_id, 'image_id': image_id,
                    'request_spec': request_spec,
                    'filter_properties': filter_properties,
                    'volume': volume, 'backup_id': backup_id}
        if not self.client.can_send_version('3.10'):
            msg_args.pop('backup_id')
        return cctxt.cast(ctxt, 'create_volume', **msg_args)
    ......
```

## cinder scheduler部分

cinder/scheduler/manager.py

```python
class SchedulerManager(manager.CleanableManager, manager.Manager):
    """Chooses a host to create volumes."""
    ......
    @objects.Volume.set_workers
    def create_volume(self, context, volume, snapshot_id=None, image_id=None,
                      request_spec=None, filter_properties=None,
                      backup_id=None):
        self._wait_for_scheduler()

        try:
            flow_engine = create_volume.get_flow(context,
                                                 self.driver,
                                                 request_spec,
                                                 filter_properties,
                                                 volume,
                                                 snapshot_id,
                                                 image_id,
                                                 backup_id)
        except Exception:
            msg = _("Failed to create scheduler manager volume flow")
            LOG.exception(msg)
            raise exception.CinderException(msg)

        with flow_utils.DynamicLogListener(flow_engine, logger=LOG):
            flow_engine.run()
    ......
```

 create_volume.get_flow

cinder/scheduler/flows/create_volume.py

```python
def get_flow(context, driver_api, request_spec=None,
             filter_properties=None,
             volume=None, snapshot_id=None, image_id=None, backup_id=None):

    """Constructs and returns the scheduler entrypoint flow.

    This flow will do the following:

    1. Inject keys & values for dependent tasks.
    2. Extract a scheduler specification from the provided inputs.
    3. Use provided scheduler driver to select host and pass volume creation
       request further.
    """
    create_what = {
        'context': context,
        'raw_request_spec': request_spec,
        'filter_properties': filter_properties,
        'volume': volume,
        'snapshot_id': snapshot_id,
        'image_id': image_id,
        'backup_id': backup_id,
    }

    flow_name = ACTION.replace(":", "_") + "_scheduler"
    scheduler_flow = linear_flow.Flow(flow_name)

    # This will extract and clean the spec from the starting values.
    scheduler_flow.add(ExtractSchedulerSpecTask(
        rebind={'request_spec': 'raw_request_spec'}))

    # This will activate the desired scheduler driver (and handle any
    # driver related failures appropriately).
    scheduler_flow.add(ScheduleCreateVolumeTask(driver_api))

    # Now load (but do not run) the flow using the provided initial data.
    return taskflow.engines.load(scheduler_flow, store=create_what)
```

flow_engine.run()

cinder/scheduler/flows/create_volume.py

```python
class ScheduleCreateVolumeTask(flow_utils.CinderTask):
    """Activates a scheduler driver and handles any subsequent failures."""
    ......
    def execute(self, context, request_spec, filter_properties, volume):
        try:
            # self.driver_api: <cinder.scheduler.filter_scheduler.FilterScheduler object at 0x7f09040f0850>
            self.driver_api.schedule_create_volume(context, request_spec,
                                                   filter_properties)
        except Exception as e:
            self.message_api.create(
                context,
                message_field.Action.SCHEDULE_ALLOCATE_VOLUME,
                resource_uuid=request_spec['volume_id'],
                exception=e)
            # An error happened, notify on the scheduler queue and log that
            # this happened and set the volume to errored out and reraise the
            # error *if* exception caught isn't NoValidBackend. Otherwise *do
            # not* reraise (since what's the point?)
            with excutils.save_and_reraise_exception(
                    reraise=not isinstance(e, exception.NoValidBackend)):
                try:
                    self._handle_failure(context, request_spec, e)
                finally:
                    common.error_out(volume, reason=e)
    ......
```

self.driver_api.schedule_create_volume

cinder/scheduler/filter_scheduler.py，选择后端主机，更新数据库，最后通过消息队列调用创建卷

```python
class FilterScheduler(driver.Scheduler):
    """Scheduler that can be used for filtering and weighing."""
    ......
    def schedule_create_volume(self, context, request_spec, filter_properties):
        # 选择后端主机
        backend = self._schedule(context, request_spec, filter_properties)

        if not backend:
            raise exception.NoValidBackend(reason=_("No weighed backends "
                                                    "available"))

        backend = backend.obj
        volume_id = request_spec['volume_id']

        # 更新数据库卷信息：host, cluster_name, scheduled_at
        updated_volume = driver.volume_update_db(context, volume_id,
                                                 backend.host,
                                                 backend.cluster_name)
        self._post_select_populate_filter_properties(filter_properties,
                                                     backend)

        # context is not serializable
        filter_properties.pop('context', None)

        self.volume_rpcapi.create_volume(context, updated_volume, request_spec,
                                         filter_properties,
                                         allow_reschedule=True)
    ......
```

cinder/volume/rpcapi.py

```python
class VolumeAPI(rpc.RPCAPI):
    """Client side of the volume rpc API."""
    ......
    def create_volume(self, ctxt, volume, request_spec, filter_properties,
                      allow_reschedule=True):
        cctxt = self._get_cctxt(volume.service_topic_queue)
        cctxt.cast(ctxt, 'create_volume',
                   request_spec=request_spec,
                   filter_properties=filter_properties,
                   allow_reschedule=allow_reschedule,
                   volume=volume)
    ......
```

## cinder volume部分

cinder/volume/manager.py

```python
class VolumeManager(manager.CleanableManager,
                    manager.SchedulerDependentManager):
    """Manages attachable block storage devices."""
    ......
    @objects.Volume.set_workers
    def create_volume(self, context, volume, request_spec=None,
                      filter_properties=None, allow_reschedule=True):
        """Creates the volume."""
        # Log about unsupported drivers
        utils.log_unsupported_driver_warning(self.driver)

        # Make sure the host in the DB matches our own when clustered
        self._set_resource_host(volume)

        # Update our allocated capacity counter early to minimize race
        # conditions with the scheduler.
        self._update_allocated_capacity(volume)
        # We lose the host value if we reschedule, so keep it here
        original_host = volume.host

        context_elevated = context.elevated()
        if filter_properties is None:
            filter_properties = {}

        if request_spec is None:
            request_spec = objects.RequestSpec()

        try:
            # NOTE(flaper87): Driver initialization is
            # verified by the task itself.
            flow_engine = create_volume.get_flow(
                context_elevated,
                self,
                # self.driver: <cinder.volume.drivers.rbd.RBDDriver object at 0x7f6a641bda90>
                self.driver,
                # self.scheduler_rpcapi: <cinder.scheduler.rpcapi.SchedulerAPI object at 0x7f6a641f9bd0>
                self.scheduler_rpcapi,
                # self.host: 'rbd:volume_high_triple@rbd_volume_high_triple'
                self.host,
                volume,
                allow_reschedule,
                context,
                request_spec,
                filter_properties,
                image_volume_cache=self.image_volume_cache,
            )
        except Exception:
            msg = _("Create manager volume flow failed.")
            LOG.exception(msg, resource={'type': 'volume', 'id': volume.id})
            raise exception.CinderException(msg)

        snapshot_id = request_spec.get('snapshot_id')
        source_volid = request_spec.get('source_volid')

        if snapshot_id is not None:
            # Make sure the snapshot is not deleted until we are done with it.
            locked_action = "%s-%s" % (snapshot_id, 'delete_snapshot')
        elif source_volid is not None:
            # Make sure the volume is not deleted until we are done with it.
            locked_action = "%s-%s" % (source_volid, 'delete_volume')
        else:
            locked_action = None

        def _run_flow():
            # This code executes create volume flow. If something goes wrong,
            # flow reverts all job that was done and reraises an exception.
            # Otherwise, all data that was generated by flow becomes available
            # in flow engine's storage.
            with flow_utils.DynamicLogListener(flow_engine, logger=LOG):
                flow_engine.run()

        # NOTE(dulek): Flag to indicate if volume was rescheduled. Used to
        # decide if allocated_capacity should be incremented.
        rescheduled = False

        try:
            if locked_action is None:
                _run_flow()
            else:
                with coordination.COORDINATOR.get_lock(locked_action):
                    _run_flow()
        finally:
            try:
                flow_engine.storage.fetch('refreshed')
            except tfe.NotFound:
                # If there's no vol_ref, then flow is reverted. Lets check out
                # if rescheduling occurred.
                try:
                    rescheduled = flow_engine.storage.get_revert_result(
                        create_volume.OnFailureRescheduleTask.make_name(
                            [create_volume.ACTION]))
                except tfe.NotFound:
                    pass

            if rescheduled:
                # NOTE(geguileo): Volume was rescheduled so we need to update
                # volume stats because the volume wasn't created here.
                # Volume.host is None now, so we pass the original host value.
                self._update_allocated_capacity(volume, decrement=True,
                                                host=original_host)

        shared_targets = (
            1
            if self.driver.capabilities.get('shared_targets', True)
            else 0)
        updates = {'service_uuid': self.service_uuid,
                   'shared_targets': shared_targets}

        volume.update(updates)
        volume.save()

        LOG.info("Created volume successfully.", resource=volume)
        return volume.id
    ......
```

create_volume.get_flow

cinder/volume/flows/manager/create_volume.py

```python
def get_flow(context, manager, db, driver, scheduler_rpcapi, host, volume,
             allow_reschedule, reschedule_context, request_spec,
             filter_properties, image_volume_cache=None):

    """Constructs and returns the manager entrypoint flow.

    This flow will do the following:

    1. Determines if rescheduling is enabled (ahead of time).
    2. Inject keys & values for dependent tasks.
    3. Selects 1 of 2 activated only on *failure* tasks (one to update the db
       status & notify or one to update the db status & notify & *reschedule*).
    4. Extracts a volume specification from the provided inputs.
    5. Notifies that the volume has started to be created.
    6. Creates a volume from the extracted volume specification.
    7. Attaches an on-success *only* task that notifies that the volume
       creation has ended and performs further database status updates.
    """

    flow_name = ACTION.replace(":", "_") + "_manager"
    volume_flow = linear_flow.Flow(flow_name)

    # This injects the initial starting flow values into the workflow so that
    # the dependency order of the tasks provides/requires can be correctly
    # determined.
    create_what = {
        'context': context,
        'filter_properties': filter_properties,
        'request_spec': request_spec,
        'volume': volume,
    }

    volume_flow.add(ExtractVolumeRefTask(db, host, set_error=False))

    retry = filter_properties.get('retry', None)

    # Always add OnFailureRescheduleTask and we handle the change of volume's
    # status when reverting the flow. Meanwhile, no need to revert process of
    # ExtractVolumeRefTask.
    do_reschedule = allow_reschedule and request_spec and retry
    volume_flow.add(OnFailureRescheduleTask(reschedule_context, db, driver,
                                            scheduler_rpcapi, do_reschedule))

    LOG.debug("Volume reschedule parameters: %(allow)s "
              "retry: %(retry)s", {'allow': allow_reschedule, 'retry': retry})

    volume_flow.add(ExtractVolumeSpecTask(db),
                    NotifyVolumeActionTask(db, "create.start"),
                    CreateVolumeFromSpecTask(manager,
                                             db,
                                             driver,
                                             image_volume_cache),
                    CreateVolumeOnFinishTask(db, "create.end"))

    # Now load (but do not run) the flow using the provided initial data.
    return taskflow.engines.load(volume_flow, store=create_what)
```

flow_engine.run()

cinder/volume/flows/manager/create_volume.py

```python
class CreateVolumeFromSpecTask(flow_utils.CinderTask):
    """Creates a volume from a provided specification.

    Reversion strategy: N/A
    """
    ......
    def execute(self, context, volume, volume_spec):
        # {'status': u'creating', 'volume_size': 10, 'volume_id': u'010df89e-24a6-4389-aa02-c2ba8f4c2348', 'type': 'raw', 'volume_name': u'volume-010df89e-24a6-4389-aa02-c2ba8f4c2348'}
        volume_spec = dict(volume_spec)
        volume_id = volume_spec.pop('volume_id', None)
        if not volume_id:
            volume_id = volume.id

        # we can't do anything if the driver didn't init
        if not self.driver.initialized:
            driver_name = self.driver.__class__.__name__
            LOG.error("Unable to create volume. "
                      "Volume driver %s not initialized", driver_name)
            raise exception.DriverNotInitialized()

        # NOTE(xyang): Populate consistencygroup_id and consistencygroup
        # fields before passing to the driver. This is to support backward
        # compatibility of consistencygroup.
        if volume.group_id:
            volume.consistencygroup_id = volume.group_id
            cg = consistencygroup.ConsistencyGroup()
            cg.from_group(volume.group)
            volume.consistencygroup = cg

        # create_type: 'raw'
        create_type = volume_spec.pop('type', None)
        LOG.info("Volume %(volume_id)s: being created as %(create_type)s "
                 "with specification: %(volume_spec)s",
                 {'volume_spec': volume_spec, 'volume_id': volume_id,
                  'create_type': create_type})
        if create_type == 'raw':
            model_update = self._create_raw_volume(volume, **volume_spec)
        elif create_type == 'snap':
            model_update = self._create_from_snapshot(context, volume,
                                                      **volume_spec)
        elif create_type == 'source_vol':
            model_update = self._create_from_source_volume(
                context, volume, **volume_spec)
        elif create_type == 'image':
            model_update = self._create_from_image(context,
                                                   volume,
                                                   **volume_spec)
        elif create_type == 'backup':
            model_update, need_update_volume = self._create_from_backup(
                context, volume, **volume_spec)
            volume_spec.update({'need_update_volume': need_update_volume})
        else:
            raise exception.VolumeTypeNotFound(volume_type_id=create_type)

        # Persist any model information provided on creation.
        try:
            if model_update:
                with volume.obj_as_admin():
                    volume.update(model_update)
                    volume.save()
        except exception.CinderException:
            # If somehow the update failed we want to ensure that the
            # failure is logged (but not try rescheduling since the volume at
            # this point has been created).
            LOG.exception("Failed updating model of volume %(volume_id)s "
                          "with creation provided model %(model)s",
                          {'volume_id': volume_id, 'model': model_update})
            raise
        return volume_spec
    ......
```

暂时分析创建裸raw盘的情况，从镜像创建盘后续再分析

self._create_raw_volume

```python
def _create_raw_volume(self, volume, **kwargs):
        try:
            ret = self.driver.create_volume(volume)
        finally:
            self._cleanup_cg_in_volume(volume)
        return ret
```

由于cinder后端卷驱动用的ceph rbd，最终通过RBDDriver实现cinder卷的真正创建

cinder/volume/drivers/rbd.py

```python
@interface.volumedriver
class RBDDriver(driver.CloneableImageVD,
                driver.MigrateVD, driver.ManageableVD, driver.BaseVD):
    """Implements RADOS block device (RBD) volume commands."""
    ......
    def create_volume(self, volume):
        """Creates a logical volume."""

        if volume.encryption_key_id:
            return self._create_encrypted_volume(volume, volume.obj_context)

        size = int(volume.size) * units.Gi

        LOG.debug("creating volume '%s'", volume.name)

        # 4194304
        chunk_size = self.configuration.rbd_store_chunk_size * units.Mi
        # 22
        order = int(math.log(chunk_size, 2))
        # 'volume-010df89e-24a6-4389-aa02-c2ba8f4c2348'
        vol_name = utils.convert_str(volume.name)

        with RADOSClient(self) as client:
            self.RBDProxy().create(client.ioctx,
                                   vol_name,
                                   size,
                                   order,
                                   old_format=False,
                                   features=client.features)

            try:
                volume_update = self._enable_replication_if_needed(volume)
            except Exception:
                self.RBDProxy().remove(client.ioctx, vol_name)
                err_msg = (_('Failed to enable image replication'))
                raise exception.ReplicationError(reason=err_msg,
                                                 volume_id=volume.id)
        return volume_update
    ......
```

CreateVolumeFromSpecTask.excute，这个函数会根据卷的不同形式来创建卷，本文分析了create_raw_volume形式，最终调用ceph后端driver创建卷。在完成创建卷后，CreateVolumeOnFinishTask这个任务会启动更新数据库，将卷更新为available状态。















































