/* Shared subnet layout helper for vis-network diagrams. */
(function (global) {
  'use strict';

  function ipToNumber(ip) {
    var p = String(ip || '').split('.');
    if (p.length !== 4 || p.some(function (v) { return !/^\d+$/.test(v) || +v > 255; })) return null;
    return (+p[0]) * 16777216 + (+p[1]) * 65536 + (+p[2]) * 256 + (+p[3]);
  }
  function numberToIp(n) {
    return [Math.floor(n / 16777216) % 256, Math.floor(n / 65536) % 256,
      Math.floor(n / 256) % 256, n % 256].join('.');
  }
  function groups(devices, prefix) {
    var size = Math.pow(2, 32 - prefix), map = {};
    devices.forEach(function (device, index) {
      var value = ipToNumber(device && device.ip), key = 'Other', net = Infinity;
      if (value !== null) { net = Math.floor(value / size) * size; key = numberToIp(net) + '/' + prefix; }
      if (!map[key]) map[key] = { key: key, net: net, members: [] };
      map[key].members.push(index);
    });
    return Object.keys(map).map(function (key) { return map[key]; }).sort(function (a, b) { return a.net - b.net; });
  }
  function options(prefix) {
    if (+prefix) return { physics: { enabled: false }, layout: { improvedLayout: false }, interaction: { hover: true, zoomView: true, tooltipDelay: 300 } };
    return { physics: { solver: 'forceAtlas2Based', forceAtlas2Based: { gravitationalConstant: -130, springLength: 170, springConstant: .04, damping: .5 }, stabilization: { iterations: 200 } }, layout: { improvedLayout: true }, interaction: { hover: true, zoomView: true, tooltipDelay: 300 } };
  }
  function apply(nodes, edges, devices, prefix, config) {
    prefix = +prefix || 0;
    if (!prefix) {
      // Flat mode is the original diagram: Gateway connects directly to every
      // scanned host.  Do not leave the graph with nodes but no edges.
      devices.forEach(function (device, index) {
        if (!nodes.filter(function (item) { return item.id === index + 1; })[0]) return;
        var ports = (device && device.ports) || [];
        edges.push({ from: 0, to: index + 1, color: { color: '#90a4ae', highlight: '#607d8b', hover: '#607d8b' }, width: 1.6, dashes: ports.length === 0, smooth: false });
      });
      return [];
    }
    config = config || {};
    var palette = ['#212529','#343a40','#495057','#5c636a','#6c757d','#3f464d'];
    var result = groups(devices, prefix).map(function (group, index) {
      var count = group.members.length, columns = Math.min(4, Math.max(1, Math.ceil(Math.sqrt(count))));
      var rows = Math.ceil(count / columns), width = Math.max(240, columns * 125 + 60);
      var x = (index - (groups(devices, prefix).length - 1) / 2) * Math.max(300, width + 55);
      return { key: group.key, members: group.members, count: count, x: x, y: -60, width: width, rows: rows,
        radius: Math.max(145, width / 2), color: palette[index % palette.length], hubId: devices.length + 1 + index };
    });
    result.forEach(function (subnet) {
      nodes.push({ id: subnet.hubId, label: '', image: config.hubIcon, shape: config.hubIcon ? 'image' : 'dot', size: 24, x: subnet.x, y: subnet.y, fixed: { x: false, y: false }, _subnet: subnet.key, title: 'Subnet ' + subnet.key + ' — ' + subnet.count + ' host(s)' });
      var gateway = typeof config.gatewayForGroup === 'function' ? config.gatewayForGroup(subnet.members.map(function (i) { return devices[i]; }), subnet) : {};
      var gatewayIp = gateway && gateway.ip;
      var hubNode = nodes[nodes.length - 1];
      hubNode.label = 'Router' + String.fromCharCode(10) + subnet.key + (gatewayIp ? String.fromCharCode(10) + gatewayIp + (gateway.isEstimated ? ' (est)' : '') : '');
      hubNode.image = config.gatewayIcon || config.hubIcon;
      hubNode.shape = (config.gatewayIcon || config.hubIcon) ? 'image' : 'dot';
      hubNode.size = 36;
      hubNode.font = { color: subnet.color, size: 12, face: 'monospace', vadjust: 7 };
      hubNode.shadow = { enabled: true, color: 'rgba(33,37,41,.24)', size: 10 };
      hubNode._isGateway = true;
      hubNode._gwIp = gatewayIp;
      hubNode._gwReason = gateway && gateway.reason;
      hubNode._device = gateway && gateway.hostIndex >= 0 ? devices[subnet.members[gateway.hostIndex]] : null;
      hubNode._portCnt = hubNode._device && hubNode._device.ports ? hubNode._device.ports.length : 0;
      hubNode._sortedPorts = hubNode._device && hubNode._device.ports
        ? hubNode._device.ports.slice().sort(function (a, b) { return (+a.port || 0) - (+b.port || 0); }) : [];
      hubNode.title = 'Gateway / Router' + String.fromCharCode(10) + 'Subnet: ' + subnet.key + (gatewayIp ? String.fromCharCode(10) + 'IP: ' + gatewayIp : '') + (gateway && gateway.reason ? String.fromCharCode(10) + 'Detection: ' + gateway.reason : '');

      // The router node above owns the detected gateway host. Remove its
      // separate device node so an address such as x.x.x.1 is not duplicated.
      if (gateway && gateway.hostIndex >= 0) {
        var gatewayNodeId = subnet.members[gateway.hostIndex] + 1;
        var gatewayNodeIndex = nodes.findIndex(function (item) { return item.id === gatewayNodeId; });
        if (gatewayNodeIndex !== -1) nodes.splice(gatewayNodeIndex, 1);
      }
      edges.push({ from: 0, to: subnet.hubId, color: { color: '#343a40', highlight: '#212529' }, width: 2.5, smooth: { type: 'cubicBezier', roundness: .16 } });
      subnet.members.forEach(function (deviceIndex, memberIndex) {
        // A detected gateway is already represented by this subnet's router
        // node.  Do not render its scanned-host node a second time.
        if (gateway && gateway.hostIndex >= 0 && deviceIndex === subnet.members[gateway.hostIndex]) return;
        var node = nodes.filter(function (item) { return item.id === deviceIndex + 1; })[0];
        if (!node) return;
        var columns = Math.min(4, Math.max(1, Math.ceil(Math.sqrt(subnet.count))));
        var column = memberIndex % columns, row = Math.floor(memberIndex / columns);
        node.x = subnet.x + (column - (columns - 1) / 2) * 125;
        node.y = subnet.y + 145 + row * 115;
        node.fixed = { x: false, y: false };
        edges.push({ from: subnet.hubId, to: deviceIndex + 1, color: { color: '#6c757d', highlight: '#343a40', opacity: .76 }, width: 1.5, dashes: false, smooth: false });
      });
    });
    return result;
  }
  function attachRegions(network, getSubnets) {
    network.__subnetGetter = getSubnets;
    function region(subnet) {
      var ids = [subnet.hubId].concat(subnet.members.map(function (index) { return index + 1; }));
      var positions = network.getPositions(ids), hub = positions[subnet.hubId];
      if (!hub) return null;
      var radius = 0;
      ids.slice(1).forEach(function (id) {
        var point = positions[id];
        if (point) radius = Math.max(radius, Math.hypot(point.x - hub.x, point.y - hub.y));
      });
      return { x: hub.x, y: hub.y, radius: Math.max(subnet.radius, radius + 60) };
    }
    network.on('beforeDrawing', function (ctx) {
      return; // Groups are separated by hierarchy and alignment, not a boundary ring.
      (getSubnets() || []).forEach(function (subnet) {
        var box = region(subnet); if (!box) return;
        ctx.save(); ctx.beginPath(); ctx.arc(box.x, box.y, box.radius, 0, 2 * Math.PI);
        ctx.fillStyle = subnet.color + '12'; ctx.fill(); ctx.setLineDash([9, 7]); ctx.lineWidth = 2; ctx.strokeStyle = subnet.color + '99'; ctx.stroke();
        ctx.setLineDash([]); ctx.font = 'bold 15px monospace'; ctx.textAlign = 'center'; ctx.fillStyle = subnet.color;
        ctx.fillText(subnet.key + ' · ' + subnet.count + (subnet.count === 1 ? ' host' : ' hosts'), box.x, box.y - box.radius - 10); ctx.restore();
      });
    });

    // Drag a subnet hub: move its hosts by the same delta, so the dotted
    // subnet boundary and all member links stay together like Ntsubnet.
    var drag = null;
    network.on('dragStart', function (event) {
      drag = null;
      if (!event.nodes || event.nodes.length !== 1) return;
      var subnet = (getSubnets() || []).filter(function (item) { return item.hubId === event.nodes[0]; })[0];
      if (!subnet) return;
      var ids = [subnet.hubId].concat(subnet.members.map(function (index) { return index + 1; }));
      drag = { hubId: subnet.hubId, ids: ids, start: network.getPositions(ids), pointer: event.pointer && event.pointer.canvas ? { x: event.pointer.canvas.x, y: event.pointer.canvas.y } : null };
    });
    function moveMembers(dx, dy) {
      if (!drag) return;
      drag.ids.forEach(function (id) {
        if (id !== drag.hubId && drag.start[id]) network.moveNode(id, drag.start[id].x + dx, drag.start[id].y + dy);
      });
    }
    network.on('dragging', function (event) {
      if (!drag || !drag.pointer || !event.pointer || !event.pointer.canvas) return;
      moveMembers(event.pointer.canvas.x - drag.pointer.x, event.pointer.canvas.y - drag.pointer.y);
    });
    network.on('dragEnd', function () {
      if (!drag) return;
      var hub = network.getPositions([drag.hubId])[drag.hubId];
      if (hub && drag.start[drag.hubId]) moveMembers(hub.x - drag.start[drag.hubId].x, hub.y - drag.start[drag.hubId].y);
      drag = null;
    });
  }
  function fit(network, animate) { network.fit({ animation: animate ? { duration: 450, easingFunction: 'easeInOutQuad' } : false }); }
  global.SubnetTopology = { apply: apply, visOptions: options, attachRegions: attachRegions, fit: fit };
})(window);
