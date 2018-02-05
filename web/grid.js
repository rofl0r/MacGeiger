Vue.component('search-box', {
	template: '#searchbox-template',
	props: {
		hidden: Boolean,
		query: String,
	},
	methods: {
		update_parent : function(query) {
			this.$emit('input', query);
		}
	}
})

Vue.component('attack-panel', {
	template: '#apanel-template',
	props: {
		active: Boolean,
		bssid: String,
		essid: String,
		channel: Number
	},
	methods : {
		unselect: function() {
			this.$emit('unselect_send_parent');
		}
	}
})

// register the grid component
Vue.component('demo-grid', {
  template: '#grid-template',
  props: {
    data: Array,
    columns: Array,
    headernames: Object,
    filterKey: String
  },
  data: function () {
    var sortOrders = {}
    this.columns.forEach(function (key) {
      sortOrders[key] = 1
    })
    return {
      sortKey: '',
      sortOrders: sortOrders
    }
  },
  computed: {
    filteredData: function () {
      var sortKey = this.sortKey
      var filterKey = this.filterKey && this.filterKey.toLowerCase()
      var order = this.sortOrders[sortKey] || 1
      var data = this.data
      if (filterKey) {
        data = data.filter(function (row) {
          return Object.keys(row).some(function (key) {
            return String(row[key]).toLowerCase().indexOf(filterKey) > -1
          })
        })
      }
      if (sortKey) {
        data = data.slice().sort(function (a, b) {
          a = a[sortKey]
          b = b[sortKey]
          return (a === b ? 0 : a > b ? 1 : -1) * order
        })
      }
      return data
    }
  },
  filters: {
    wps_version: function(x) {
      if(!x) return "";
      return (x >> 4).toString() + "." + (x & 0xf).toString();
    },
    capitalize: function (str) {
      return str.charAt(0).toUpperCase() + str.slice(1)
    }
  },
  methods: {
    sortBy: function (key) {
      this.sortKey = key
      this.sortOrders[key] = this.sortOrders[key] * -1
    },
	select_click: function(bssid) {
		this.$emit('select_bssid', bssid);
	}

  }
})

// bootstrap the demo
var demo = new Vue({
	el: '#demo',
	data: {
		searchQuery: '',
		oldQuery: '',
		selected: false,
		gridColumns: [
			'bssid',
			'essid',
			'channel',
			'rssi',
			'wps_version',
			//'wps_state',
			'wps_locked',
			'wps_manufacturer',
			'wps_model_name',
			'wps_model_number',
			'wps_device_name',
			'wps_serial'
			/*
			'wps_uuid',
			'wps_response_type',
			'wps_primary_device_type',
			'wps_config_methods'
			*/
		],
		gridData: [
			{
				'bssid': 0, 'essid': '', 'channel':0, 'rssi':0, 'wps_version':0,
				'wps_locked':0, 'wps_state':0,
				'wps_manufacturer':'', 'wps_model_name':'', 'wps_model_number':'',
				'wps_device_name':'', 'wps_serial':'', 'wps_uuid':'',
				'wps_response_type':'', 'wps_primary_device_type': '',
				'wps_config_methods':''
			}
		],
		gridHeaders: {
			'bssid':'bssid',
			'essid':'essid',
			'channel':'ch',
			'rssi':'dbm',
			'wps_version':'wps',
			'wps_locked':'lck',
			'wps_manufacturer':'manuf',
			'wps_model_name':'model',
			'wps_model_number':'model#',
			'wps_device_name':'device',
			'wps_serial':'serial',
		},
		interval: null,
	},
	methods: {
		loadDataAll: function () {
			fetch('/api/full')
			.then(response => response.json())
			.then(json => {
				this.gridData = json.wifis
			})
		},
		loadDataAll2: function () {
			fetch('/api/full')
			.then(response => response.json())
			.then(json => {
				this.gridData = json.wifis
			})
		},
		installTimer: function (secs) {
			console.log("ready");
			this.loadDataAll();
			this.interval = setInterval(function () {
				this.loadDataAll2();
			}.bind(this), secs*1000);
		},
		update_query : function(query) {
			this.searchQuery = query;
		},
		select: function (bssid) {
			this.oldQuery = this.searchQuery;
			this.searchQuery = bssid;
			this.selected = true;
			fetch("/api/select/" + bssid)
		},
		app_unselect: function () {
			this.searchQuery = this.oldQuery;
			this.selected = false;
			fetch("/api/unselect")
		}
	},
	mounted: function () {
		this.$nextTick(function () {
		// Code that will run only after the
		// entire view has been rendered
			this.installTimer(2);
		})
	},
	beforeDestroy: function() {
		clearInterval(this.interval);
	},
	created() {
		this.loadDataAll()
	}
})

