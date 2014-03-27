// This is a manifest file that'll be compiled into application.js, which will include all the files
// listed below.
//
// Any JavaScript/Coffee file within this directory, lib/assets/javascripts, vendor/assets/javascripts,
// or vendor/assets/javascripts of plugins, if any, can be referenced here using a relative path.
//
// It's not advisable to add code directly here, but if you do, it'll appear at the bottom of the
// compiled file.
//
// Read Sprockets README (https://github.com/sstephenson/sprockets#sprockets-directives) for details
// about supported directives.
//
//= require jquery
//= require jquery_ujs
//= require turbolinks
//= require bootstrap
//= require_tree .

function generate_freq_bars(selector, data) {
  var svg = dimple.newSvg(selector, 1900, 500);
  var myChart = new dimple.chart(svg, data);
  myChart.setBounds(70, 40, 1590, 320)
  var x = myChart.addCategoryAxis("x", "Name");
  var y = myChart.addMeasureAxis("y", "Change");
  var s = myChart.addSeries("Name", dimple.plot.bar);
  //var myLegend = myChart.addLegend(1800, 20, 60, 500, "right");

  s.addEventHandler("mouseover", function(e) {
    generic_onHover(e, svg);
  });
  s.addEventHandler("mouseleave", function(e) {
    generic_onLeave(e, svg);
  });

  myChart.draw();
  s.shapes.each(function(d) {
    // Get the shape as a d3 selection
    var shape = d3.select(this),
      // Get the height and width from the scales
      height = myChart.y + myChart.height - y._scale(d.height);
      width = d.width + 40;
    // Only label bars where the text can fit
    if (height >= 8) {
      // Add a text label for the value
      svg.append("text")
        // Position in the centre of the shape (vertical position is
        // manually set due to cross-browser problems with baseline)
        .attr("x", parseFloat(shape.attr("x")) + width / 2)
        .attr("y", parseFloat(shape.attr("y")) - height / 2 + 3.5)
        // Centre align
        .style("text-anchor", "middle")
        .style("font-size", "10px")
        .style("font-family", "sans-serif")
        // Make it a little transparent to tone down the black
        .style("opacity", 0.6)
        // Format the number
        .text(d3.format("f")(d.yValue) + "h\n" + "");
        console.log(d);
    }
  });
}

function generate_time_bars(selector, data) {
  var svg = dimple.newSvg(selector, 1900, 500);
  var myChart = new dimple.chart(svg, data);
  myChart.setBounds(70, 40, 1590, 320)
  var x = myChart.addTimeAxis("x", "Time", "%d %b %Y", "%d %b %Y");
  x.addOrderRule("Time");
  var y = myChart.addMeasureAxis("y", "Change");
  var s = myChart.addSeries(["Name"], dimple.plot.bar);
  var myLegend = myChart.addLegend(1800, 20, 60, 500, "right");
  
  myChart.draw();

  myChart.legends = [];
  var filterValues = dimple.getUniqueValues(data, "Name");
  myLegend.shapes.selectAll("rect")
    .on("click", function (e) {
      var hide = false;
      var newFilters = [];
      filterValues.forEach(function (f) {
        if (f === e.aggField.slice(-1)[0]) {
          hide = true;
        } else {
          newFilters.push(f);
        }
      });
      if (hide) {
        d3.select(this).style("opacity", 0.2);
      } else {
        newFilters.push(e.aggField.slice(-1)[0]);
        d3.select(this).style("opacity", 0.8);
      }
      filterValues = newFilters;
      myChart.data = dimple.filterData(data, "Name", filterValues);
      myChart.draw(800);
    });

  s.addEventHandler("mouseover", function(e) {
    generic_onHover(e, svg);
  });
  s.addEventHandler("mouseleave", function(e) {
    generic_onLeave(e, svg);
  });

  myChart.draw();
}

function generic_onHover(e, svg) {
  var cx = parseFloat(e.selectedShape.attr("x")),
      cy = parseFloat(e.selectedShape.attr("y"));
  var width = 150,
    height = 40,
    x = (cx + width + 10 < svg.attr("width") ?
      cx + 10 :
      cx - width - 20);
    y = (cy - height / 2 < 0 ?
      15 :
      cy - height / 2);

  popup = svg.append("g");
  svg._popup = popup;

  popup
    .append("rect").attr("x", x + 5).attr("y", y - 5).attr("width", 150)
    .attr("height", height).attr("rx", 5).attr("ry", 5)
    .style("fill", 'white').style("stroke", 'black').style("stroke-width", 1);

  popup
    .append('text').attr('x', x + 0).attr('y', y + 10)
    .append('tspan').attr('x', x + 10).attr('y', y + 8)
    .text(e.seriesValue[0] + "\n")
    .style("font-family", "sans-serif").style("font-size", 10)
    .append('tspan').attr('x', x + 10).attr('y', y + 22)
    .text('Change ' + Math.round(e.yValue * 10) / 10)
    .style("font-family", "sans-serif").style("font-size", 10)
}

function generic_onLeave(e, svg) {
  popup = svg._popup;
  svg._popup = null;

  if (popup !== null) {
      popup.remove();
  }
};