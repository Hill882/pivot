export class JobManager {
  constructor() {
    this.$elements = {
      jobSearchInput: $("#job-search-input"),
      dropDownCaret: $("#joblist-dropdown"),
      createJobButton: $("#create-job-button"),
      modal: $("#jobModal"),
      closeModalHeader: $("#close-modal"),
      closeModalButton: $("#cancel-modal-button"),
      jobListContainer: $("#dropdown-menu"),
      jobNameInput: $("#job-name"),
      companyNameInput: $("#company-name"),
    };
    this.jobList = [];
    this.dropDownMenuOpen = false;

    this.addEventListeners();
    $(document).ready(this.initDropdown.bind(this));

    $(document).ready(() => {
      this.resetFormValues(); // Reset form values on page load
    });
  }

  addEventListeners() {
    const { createJobButton, closeModalButton, closeModalHeader, modal } = this.$elements;
    createJobButton.on('click', this.openModal.bind(this));
    closeModalButton.on('click', this.closeModal.bind(this));
    closeModalHeader.on('click', this.closeModal.bind(this));
  }

  async fetchJobs() {
    try {
      const response = await fetch("/jobs");
      console.log(response)
      if (!response.ok) {
        throw new Error(`Http error! status: ${response.status}`);
      }
      const jobs = await response.json();
      this.jobList = jobs; // Assign jobs directly
      this.populateDropdown(this.jobList);
    } catch (error) {
      console.error("Failed to fetch jobs", error);
    }
  }

  resetFormValues() {
    const { companyNameInput, jobNameInput } = this.$elements;
    jobNameInput.val("");
    companyNameInput.val("");
  }

  openModal() {
    this.$elements.modal.show();
  }

  closeModal() {
    this.resetFormValues();
    this.$elements.modal.hide();
  }

  initDropdown() {
    $.getJSON('/jobs', (data) => { this.jobList = data; });

    this.$elements.dropDownCaret.on('click', (event) => {
      event.stopPropagation();
      this.toggleDropdown();
    });

    this.$elements.jobSearchInput.on('click', (event) => {
      event.stopPropagation();
      this.$elements.jobSearchInput.val('');
      this.toggleDropdown();
      this.initAutocomplete();
    });

    $(document).on('click', (event) => {
      if (this.dropDownMenuOpen) {
        const isDropdownClick = $(event.target).closest('#dropdown-menu').length > 0;
        if (!isDropdownClick) this.toggleDropdown();
      }
    });
  }

  populateDropdown(items) {
    console.log(items)
    const { jobListContainer } = this.$elements;
    jobListContainer.empty();

    if (items.length === 0) {
      const listItem = $(`<li>No jobs</li>`);
      listItem.css('border-bottom', 'none');
      jobListContainer.append(listItem);
    } else {
      items.forEach((item, index) => {
        const listItem = $(`<a href="/map/${item.id}"><li>${item.job_name}</li></a>`);

        if (index === items.length - 1) {
          listItem.find('li').css('border-bottom', 'none');
        }

        jobListContainer.append(listItem);
      });
    }
  }

  toggleDropdown() {
    this.dropDownMenuOpen = !this.dropDownMenuOpen;
    this.populateDropdown(this.jobList);
    this.$elements.jobListContainer.toggleClass('hidden');
  }

  initAutocomplete() {
    const { jobSearchInput } = this.$elements;
    const jobNames = this.jobList.map(job => job.name);

    jobSearchInput.autocomplete({
      source: jobNames,
      select: (event, ui) => {
        const selectedJob = this.jobList.find(job => job.name === ui.item.value);
        if (selectedJob) {
          window.location.href = `/map/${selectedJob.id}`; // Redirect to job detail page
        }
      }
    });
  }
}

$(document).ready(() => {
  const jobManager = new JobManager();
  jobManager.fetchJobs();
});
